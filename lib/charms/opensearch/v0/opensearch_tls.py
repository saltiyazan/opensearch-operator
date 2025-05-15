# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this class we manage certificates relation.

This class handles certificate request and renewal through
the interaction with the TLS Certificates Operator.

This library needs https://charmhub.io/tls-certificates-interface/libraries/tls_certificates
library is imported to work.

It requires a charm that extends OpenSearchBaseCharm as it refers internal objects of that class.
— update_config: to disable TLS when relation with the TLS Certificates Operator is broken.
"""

import base64
import logging
import os
import re
import socket
import tempfile
import typing
from os.path import exists
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union

from charms.opensearch.v0.constants_charm import (
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
    PeerRelationName,
)
from charms.opensearch.v0.constants_tls import (
    ADMIN_TLS_RELATION,
    CLIENT_TLS_RELATION,
    TRANSPORT_TLS_RELATION,
    ADMIN_CA_ALIAS,
    TRANSPORT_CA_ALIAS,
    HTTP_CA_ALIAS,
    OLD_ADMIN_CA_ALIAS,
    OLD_TRANSPORT_CA_ALIAS,
    OLD_HTTP_CA_ALIAS,
    CA_TRUSTSTORE_NAME,
    CertType,
)
from charms.opensearch.v0.helper_charm import all_units, run_cmd
from charms.opensearch.v0.helper_networking import get_host_public_ip
from charms.opensearch.v0.helper_security import generate_password
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
    OpenSearchHttpError,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.tls_certificates_interface.v4.tls_certificates import (
    CertificateAvailableEvent,
    CertificateRequestAttributes,
    CertificateSigningRequest,
    Mode,
    TLSCertificatesRequiresV4,
)
from ops.charm import ActionEvent, RelationBrokenEvent, RelationCreatedEvent
from ops.framework import Object

if typing.TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

# The unique Charmhub library identifier, never change it
LIBID = "8bcf275287ad486db5f25a1dbb26f920"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


CA_ALIAS = "ca"
OLD_CA_ALIAS = f"old-{CA_ALIAS}"


logger = logging.getLogger(__name__)


class OpenSearchTLS(Object):
    """Class that Manages OpenSearch relation with TLS Certificates Operator."""

    def __init__(
        self, charm: "OpenSearchBaseCharm", peer_relation: str, jdk_path: str, certs_path: str
    ):
        super().__init__(charm, "tls-component")

        self.charm = charm
        self.peer_relation = peer_relation
        self.jdk_path = jdk_path
        self.certs_path = certs_path
        self.keytool = "opensearch.keytool"
        self.admin_certs = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=ADMIN_TLS_RELATION,
            certificate_requests=self._get_admin_certificate_requests(),
            mode=Mode.APP,
            refresh_events=[
                self.on.config_changed,
            ],
        )
        self.transport_certs = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=TRANSPORT_TLS_RELATION,
            certificate_requests=self._get_unit_certificate_requests(CertType.UNIT_TRANSPORT),
            mode=Mode.UNIT,
            refresh_events=[
                self.on.config_changed,
            ],
        )
        self.client_certs = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=CLIENT_TLS_RELATION,
            certificate_requests=self._get_unit_certificate_requests(CertType.UNIT_HTTP),
            mode=Mode.UNIT,
            refresh_events=[
                self.on.config_changed,
            ],
        )

        self.framework.observe(
            self.charm.on.set_tls_private_key_action, self._on_set_tls_private_key
        )

        for relation_name in [ADMIN_TLS_RELATION, TRANSPORT_TLS_RELATION, CLIENT_TLS_RELATION]:
            self.framework.observe(
                self.charm.on[relation_name].relation_created, self._on_tls_relation_created
            )
            self.framework.observe(
                self.charm.on[relation_name].relation_broken, self._on_tls_relation_broken
            )

        for cert_requirer in [self.admin_certs, self.transport_certs, self.client_certs]:
            self.framework.observe(
                cert_requirer.on.certificate_available, self._on_certificate_available
            )

    def _get_admin_certificate_requests(self, allow_non_leader: bool = False) -> List[CertificateRequestAttributes]:
        """Get the certificate requests for the admin certificate."""
        if not self.charm.unit.is_leader() and not allow_non_leader:
            logger.warning("Admin certificates are only available on the leader unit")
            return []
        if not self.charm.opensearch_peer_cm.deployment_desc() or not self.model.get_relation(
            self.peer_relation
        ):
            return []
        return [
            CertificateRequestAttributes(
                common_name="admin",
                organization=self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name,
                sans_oid=frozenset(self._get_sans(CertType.APP_ADMIN).get("sans_oid")),
                add_unique_id_to_subject_name=False,
                add_unique_id_to_non_critical_extension=True,
            )
        ]

    def _get_unit_certificate_requests(
        self, cert_type: CertType
    ) -> List[CertificateRequestAttributes]:
        if not self.charm.opensearch_peer_cm.deployment_desc() or not self.model.get_relation(
            self.peer_relation
        ):
            return []
        sans = self._get_sans(cert_type)
        return [
            CertificateRequestAttributes(
                common_name=self._get_common_name(cert_type),
                organization=self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name,
                sans_oid=frozenset(sans.get("sans_oid")),
                sans_dns=frozenset(sans.get("sans_dns")),
                sans_ip=frozenset(sans.get("sans_ip")),
                add_unique_id_to_subject_name=False,
                add_unique_id_to_non_critical_extension=True,
            )
        ]

    def _on_set_tls_private_key(self, event: ActionEvent) -> None:
        # For some reason only works on the second attempt
        """Set the TLS private key, which will be used for requesting the certificate."""
        if not self.charm.opensearch_peer_cm.deployment_desc():
            event.fail("The action can only be run once the deployment is complete.")
            return
        if self.charm.upgrade_in_progress:
            event.fail("Setting private key not supported while upgrade in-progress")
            return

        cert_type = CertType(event.params["category"])  # type
        scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
        if scope == Scope.APP and not (
            self.charm.unit.is_leader()
            and self.charm.opensearch_peer_cm.deployment_desc().typ
            == DeploymentType.MAIN_ORCHESTRATOR
        ):
            event.log(
                "Only the juju leader unit of the main orchestrator can set private key for the admin certificates."
            )
            return

        try:
            if scope == Scope.APP and cert_type == CertType.APP_ADMIN:
                self.admin_certs.regenerate_private_key()
            elif scope == Scope.UNIT and cert_type == CertType.UNIT_TRANSPORT:
                self.transport_certs.regenerate_private_key()
            elif scope == Scope.UNIT and cert_type == CertType.UNIT_HTTP:
                self.client_certs.regenerate_private_key()
            else:
                raise ValueError(f"Invalid certificate type: {cert_type}")
        except ValueError as e:
            event.fail(str(e))

    def request_new_admin_certificate(self) -> None:
        """Request the generation of a new admin certificate."""
        self.charm.peers_data.delete(Scope.UNIT, f"{CertType.APP_ADMIN.val}_tls_configured")
        if not self.charm.unit.is_leader():
            return
        certificate_attributes = self._get_admin_certificate_requests()[0]
        provider_certificate, _ = self.admin_certs.get_assigned_certificate(certificate_attributes)
        if not provider_certificate:
            logger.error("No provider certificate found for admin certificate when storing latest admin certificate")
            return
        self.admin_certs.renew_certificate(provider_certificate)

    def request_new_unit_certificates(self, cert_type: CertType) -> None:
        """Requests a new certificate with the given scope and type from the tls operator."""
        self.charm.peers_data.delete(Scope.UNIT, f"{cert_type.val}_tls_configured")

        if cert_type == CertType.UNIT_HTTP:
            certificate_attributes = self._get_unit_certificate_requests(CertType.UNIT_HTTP)[0]
            provider_certificate, _ = self.client_certs.get_assigned_certificate(certificate_attributes)
            if not provider_certificate:
                logger.error("No provider certificate found for client certificate when storing latest unit certificate")
            else:
                self.client_certs.renew_certificate(provider_certificate)
        elif cert_type == CertType.UNIT_TRANSPORT:
            certificate_attributes = self._get_unit_certificate_requests(CertType.UNIT_TRANSPORT)[0]
            provider_certificate, _ = self.transport_certs.get_assigned_certificate(certificate_attributes)
            if not provider_certificate:
                logger.error("No provider certificate found for transport certificate when storing latest unit certificate")
            else:
                self.transport_certs.renew_certificate(provider_certificate)
        else:
            return

    def _on_tls_relation_created(self, event: RelationCreatedEvent) -> None:
        """Request certificate when TLS relation created."""
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
            event.defer()
            return
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            event.defer()
            return
        admin_secrets = (
            self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            # create passwords for both ca trust_store/admin key_store
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, "ca")
            self._create_keystore_pwd_if_not_exists(
                Scope.APP, CertType.APP_ADMIN, CertType.APP_ADMIN.val
            )

        elif not admin_secrets.get("truststore-password"):
            logger.debug("Truststore-password from main-orchestrator not available yet.")
            event.defer()
            return

        # create passwords for both unit-http/transport key_stores
        self._create_keystore_pwd_if_not_exists(
            Scope.UNIT, CertType.UNIT_TRANSPORT, CertType.UNIT_TRANSPORT.val
        )
        self._create_keystore_pwd_if_not_exists(
            Scope.UNIT, CertType.UNIT_HTTP, CertType.UNIT_HTTP.val
        )

    def _on_tls_relation_broken(self, event: RelationBrokenEvent) -> None:
        """Notify the charm that the relation is broken."""
        if self.charm.upgrade_in_progress:
            logger.warning(
                "Modifying relations during an upgrade is not supported. The charm may be in a broken, unrecoverable state"
            )
        self.charm.on_tls_relation_broken(event)

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:  # noqa: C901
        """Enable TLS when TLS certificate available.

        CertificateAvailableEvents fire whenever a new certificate is created by the TLS charm.
        """
        certificate_signing_request = CertificateSigningRequest.from_string(
            str(event.certificate_signing_request)
        )
        certificate_attributes = CertificateRequestAttributes.from_csr(
            certificate_signing_request, False
        )
        if certificate_attributes in self._get_admin_certificate_requests(allow_non_leader=True):
            scope = Scope.APP
            cert_type = CertType.APP_ADMIN
            _, pk = self.admin_certs.get_assigned_certificate(certificate_attributes)
            logger.info("Admin Certificate Available")
        elif certificate_attributes in self._get_unit_certificate_requests(
            CertType.UNIT_TRANSPORT
        ):
            scope = Scope.UNIT
            cert_type = CertType.UNIT_TRANSPORT
            _, pk = self.transport_certs.get_assigned_certificate(certificate_attributes)
            logger.info("Transport Certificate Available")
        elif certificate_attributes in self._get_unit_certificate_requests(CertType.UNIT_HTTP):
            scope = Scope.UNIT
            cert_type = CertType.UNIT_HTTP
            _, pk = self.client_certs.get_assigned_certificate(certificate_attributes)
            logger.info("Client Certificate Available")
        else:
            logger.info("Unknown certificate available.")
            return
        admin_secrets = (
            self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        if scope == Scope.APP and not self.charm.unit.is_leader():
            if not admin_secrets.get("cert") or not admin_secrets.get("chain") or not admin_secrets.get("ca-cert"):
                event.defer()
                return
            self.store_admin_tls_secrets_if_applies()
        if scope != Scope.APP:
            # If admin cert not available we need to defer, otherwise it will never be stored
            if not admin_secrets.get("cert"):
                logger.info("Admin certificate not available yet. Waiting for next events.")
                event.defer()
                return
        self.charm.secrets.put_object(
            scope=scope,
            key=cert_type.val,
            value={
                "key": str(pk),
                "csr": str(event.certificate_signing_request),
                "subject": f"/O={self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name}/CN={certificate_attributes.common_name}",
            },
            merge=True,
        )
        secrets = self.charm.secrets.get_object(scope, cert_type.val, peek=True) or {}

        old_cert = secrets.get("cert", None)
        ca_chain = "\n".join(str(cert) for cert in event.chain[::-1])

        if secrets.get("chain") != ca_chain or secrets.get("ca-cert") != str(event.ca):
            # Juju is not able to check if secrets' content changed between revisions
            # this IF is intended to reduce a storm of secret-removed/-changed events
            # for the same content
            self.charm.secrets.put_object(
                scope,
                cert_type.val,
                {
                    "chain": ca_chain,
                    "ca-cert": str(event.ca),
                },
                merge=True,
            )

        current_stored_ca = self.read_stored_ca(cert_type, old=False)
        if current_stored_ca != str(event.ca):
            if not self.store_new_ca(
                self.charm.secrets.get_object(scope, cert_type.val, peek=True),
                cert_type
            ):
                logger.debug("Could not store new CA certificate.")
                event.defer()
                return
            # replacing the current CA initiates a rolling restart and certificate renewal
            # the workflow is the following:
            # get new CA -> set tls_ca_renewing -> restart -> post_start_init -> set tls_ca_renewed
            # -> request new certs -> get new certs -> on_tls_conf_set
            # -> delete both tls_ca_renewing and tls_ca_renewed
            if current_stored_ca:
                self.charm.peers_data.put(Scope.UNIT, f"{cert_type.val}_tls_ca_renewing", True)
                self.update_ca_rotation_flag_to_peer_cluster_relation(
                    flag=f"{cert_type.val}_tls_ca_renewing", operation="add"
                )
                self.charm.on_tls_ca_rotation()
                return

        if secrets.get("cert") != str(event.certificate):
            self.charm.secrets.put_object(
                scope,
                cert_type.val,
                {
                    "cert": str(event.certificate),
                },
                merge=True,
            )
        # store the certificates and keys in a key store
        if not self.store_new_tls_resources(
            cert_type, self.charm.secrets.get_object(scope, cert_type.val, peek=True)
        ):
            event.defer()
            return

        # apply the chain.pem file for API requests, only if the CA cert has not been updated
        if admin_secrets.get("chain") and not self.read_stored_ca(cert_type=CertType.APP_ADMIN, old=True):
            self.update_request_ca_bundle(cert_type)

        for relation in self.charm.opensearch_provider.relations:
            try:
                self.charm.opensearch_provider.update_certs(relation.id, ca_chain)
            except KeyError:
                # As we are setting the ca_chain, it should not be likely to happen a KeyError at
                # update_certs. This logic is left for a very corner case.
                logger.error("Error updating certificates in the relation: ca_chain not set.")
                event.defer()
                return

        # broadcast secret updates for certs and CA to related sub-clusters
        if self.charm.unit.is_leader() and self.charm.opensearch_peer_cm.is_provider(typ="main"):
            self.charm.peer_cluster_provider.refresh_relation_data(event, can_defer=False)

        renewal = self.read_stored_ca(cert_type=cert_type, old=True) is not None or (
            old_cert is not None and old_cert != str(event.certificate)
        )

        try:
            self.charm.on_tls_conf_set(event, scope, cert_type, renewal)
        except OpenSearchError as e:
            logger.exception(e)
            event.defer()

    def _get_sans(self, cert_type: CertType) -> Dict[str, List[str]]:
        """Create a list of OID/IP/DNS names for an OpenSearch unit.

        Returns:
            A list representing the hostnames of the OpenSearch unit.
            or None if admin cert_type, because that cert is not tied to a specific host.
        """
        sans = {"sans_oid": ["1.2.3.4.5.5"]}  # required for node discovery
        if cert_type == CertType.APP_ADMIN:
            return sans

        # We add the cert_type to the subject name to avoid conflicts between unit-http and unit-transport
        # This won't be accepted by CAs like Let's Encrypt, but since we are adding IP addresses, that aren't accepted by Let's Encrypt either, it's fine
        dns = {self.charm.unit_name, socket.gethostname(), socket.getfqdn(), cert_type.val}
        ips = {self.charm.unit_ip}

        host_public_ip = get_host_public_ip()
        if cert_type == CertType.UNIT_HTTP and host_public_ip:
            ips.add(host_public_ip)

        for ip in ips.copy():
            try:
                name, aliases, addresses = socket.gethostbyaddr(ip)
                ips.update(addresses)

                dns.add(name)
                dns.update(aliases)
            except (socket.herror, socket.gaierror):
                continue

        sans["sans_ip"] = [ip for ip in ips if ip.strip()]
        sans["sans_dns"] = [entry for entry in dns if entry.strip()]

        return sans

    def _get_common_name(self, cert_type: CertType) -> str:
        """Get subject of the certificate."""
        if cert_type == CertType.APP_ADMIN:
            cn = "admin"
        else:
            cn = self.charm.unit_ip

        return cn

    @staticmethod
    def _parse_tls_file(raw_content: str) -> bytes:
        """Parse TLS files from both plain text or base64 format."""
        if re.match(r"(-+(BEGIN|END) [A-Z ]+-+)", raw_content):
            return re.sub(
                r"(-+(BEGIN|END) [A-Z ]+-+)",
                "\\1",
                raw_content,
            ).encode("utf-8")
        return base64.b64decode(raw_content)

    def _find_secret(
        self, event_data: str, secret_name: str
    ) -> Optional[Tuple[Scope, CertType, Dict[str, str]]]:
        """Find secret across all scopes (app, unit) and across all cert types.

        Returns:
            scope: scope type of the secret.
            cert type: certificate type of the secret (APP_ADMIN, UNIT_HTTP etc.)
            secret: dictionary of the data stored in this secret
        """

        def is_secret_found(secrets: Optional[Dict[str, str]]) -> bool:
            return (
                secrets is not None
                and secrets.get(secret_name, "").rstrip() == event_data.rstrip()
            )

        app_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if is_secret_found(app_secrets):
            return Scope.APP, CertType.APP_ADMIN, app_secrets

        u_transport_secrets = self.charm.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, peek=True
        )
        if is_secret_found(u_transport_secrets):
            return Scope.UNIT, CertType.UNIT_TRANSPORT, u_transport_secrets

        u_http_secrets = self.charm.secrets.get_object(
            Scope.UNIT, CertType.UNIT_HTTP.val, peek=True
        )
        if is_secret_found(u_http_secrets):
            return Scope.UNIT, CertType.UNIT_HTTP, u_http_secrets

        return None

    def get_unit_certificates(self) -> Dict[CertType, str]:
        """Retrieve the list of certificates for this unit."""
        certs = {}

        transport_secrets = self.charm.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, peek=True
        )
        if transport_secrets and transport_secrets.get("cert"):
            certs[CertType.UNIT_TRANSPORT] = transport_secrets["cert"]

        http_secrets = self.charm.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val, peek=True)
        if http_secrets and http_secrets.get("cert"):
            certs[CertType.UNIT_HTTP] = http_secrets["cert"]

        if self.charm.unit.is_leader():
            admin_secrets = self.charm.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
            if admin_secrets and admin_secrets.get("cert"):
                certs[CertType.APP_ADMIN] = admin_secrets["cert"]

        return certs

    def _create_keystore_pwd_if_not_exists(self, scope: Scope, cert_type: CertType, alias: str):
        """Create passwords for the key stores if not already created."""
        store_pwd = None
        store_type = "truststore" if alias == "ca" else "keystore"

        secrets = self.charm.secrets.get_object(scope, cert_type.val, peek=True)
        if secrets:
            store_pwd = secrets.get(f"{store_type}-password")

        if not store_pwd and not (
            self.charm.opensearch_peer_cm.is_consumer(of="main")
            and cert_type == CertType.APP_ADMIN
        ):
            self.charm.secrets.put_object(
                scope,
                cert_type.val,
                {f"{store_type}-password": generate_password()},
                merge=True,
            )

    def store_new_ca(self, secrets: Dict[str, Any], cert_type: CertType) -> bool:  # noqa: C901
        """Add new CA cert to trust store."""
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            return False

        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, "ca")

        admin_secrets = (
            self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )

        if not ((secrets or {}).get("ca-cert") and admin_secrets.get("truststore-password")):
            logging.error("CA cert  or truststore-password not found, quitting.")
            return False

        if cert_type == CertType.APP_ADMIN:
            ca_alias = ADMIN_CA_ALIAS
            old_ca_alias = OLD_ADMIN_CA_ALIAS
        elif cert_type == CertType.UNIT_TRANSPORT:
            ca_alias = TRANSPORT_CA_ALIAS
            old_ca_alias = OLD_TRANSPORT_CA_ALIAS
        elif cert_type == CertType.UNIT_HTTP:
            ca_alias = HTTP_CA_ALIAS
            old_ca_alias = OLD_HTTP_CA_ALIAS
        else:
            logger.error(f"Invalid certificate type: {cert_type}")
            return False

        store_path = f"{self.certs_path}/{CA_TRUSTSTORE_NAME}"

        try:
            run_cmd(
                f"""{self.keytool} -changealias \
                -alias {ca_alias} \
                -destalias {old_ca_alias} \
                -keystore {store_path} \
                -storetype PKCS12
            """,
                f"-storepass {admin_secrets.get('truststore-password')}",
            )
            logger.info(f"Current CA {ca_alias} was renamed to old-{ca_alias}.")
        except OpenSearchCmdError as e:
            # This message means there was no "ca" alias or store before, if it happens ignore
            if not (
                f"Alias <{ca_alias}> does not exist" in e.out
                or "Keystore file does not exist" in e.out
            ):
                raise

        with tempfile.NamedTemporaryFile(
            mode="w+t", dir=self.charm.opensearch.paths.conf
        ) as ca_tmp_file:
            ca_tmp_file.write(secrets.get("ca-cert"))
            ca_tmp_file.flush()

            try:
                run_cmd(
                    f"""{self.keytool} -importcert \
                    -trustcacerts \
                    -noprompt \
                    -alias {ca_alias} \
                    -keystore {store_path} \
                    -file {ca_tmp_file.name} \
                    -storetype PKCS12
                """,
                    f"-storepass {admin_secrets.get('truststore-password')}",
                )
                run_cmd(f"sudo chmod +r {store_path}")
                logger.info(f"New CA was added to truststore with alias {ca_alias}.")
            except OpenSearchCmdError as e:
                logging.error(f"Error storing the ca-cert: {e}")
                return False

        self._add_ca_to_request_bundle(secrets.get("chain"), cert_type)

        return True

    def read_stored_ca(self, cert_type: CertType = CertType.APP_ADMIN, old: bool = False) -> Optional[str]:
        """Load stored CA cert.
        
        Args:
            cert_type: The type of certificate to load.
            old: Whether to load the old CA cert.
        """
        if cert_type == CertType.APP_ADMIN:
            ca_alias = ADMIN_CA_ALIAS if not old else OLD_ADMIN_CA_ALIAS
        elif cert_type == CertType.UNIT_TRANSPORT:
            ca_alias = TRANSPORT_CA_ALIAS if not old else OLD_TRANSPORT_CA_ALIAS
        elif cert_type == CertType.UNIT_HTTP:
            ca_alias = HTTP_CA_ALIAS if not old else OLD_HTTP_CA_ALIAS
        else:
            logger.error(f"Invalid certificate type: {cert_type}")
            return None

        ca_trust_store = f"{self.certs_path}/{CA_TRUSTSTORE_NAME}"

        secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)

        if not (exists(ca_trust_store) and secrets):
            return None

        try:
            stored_certs = run_cmd(
                f"openssl pkcs12 -in {ca_trust_store}",
                f"-passin pass:{secrets.get('truststore-password')}",
            ).out
        except OpenSearchCmdError as e:
            logging.error(f"Error reading the current truststore: {e}")
            return

        # parse output to retrieve the current CA (in case there are many)
        start_cert_marker = "-----BEGIN CERTIFICATE-----"
        end_cert_marker = "-----END CERTIFICATE-----"
        certificates = stored_certs.split(end_cert_marker)
        for cert in certificates:
            if f"friendlyName: {ca_alias}" in cert:
                return f"{start_cert_marker}{cert.split(start_cert_marker)[1]}{end_cert_marker}"

        return None

    def remove_old_ca(self, cert_type: CertType = CertType.APP_ADMIN) -> None:
        """Remove old CA cert from trust store."""
        if cert_type == CertType.APP_ADMIN:
            alias = OLD_ADMIN_CA_ALIAS
        elif cert_type == CertType.UNIT_TRANSPORT:
            alias = OLD_TRANSPORT_CA_ALIAS
        elif cert_type == CertType.UNIT_HTTP:
            alias = OLD_HTTP_CA_ALIAS
        else:
            logger.error(f"Invalid certificate type: {cert_type}")
            return
        ca_trust_store = f"{self.certs_path}/{CA_TRUSTSTORE_NAME}"

        secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        store_pwd = secrets.get("truststore-password")

        try:
            run_cmd(
                f"""{self.keytool} \
                -list \
                -keystore {ca_trust_store} \
                -storepass {store_pwd} \
                -alias {alias} \
                -storetype PKCS12"""
            )
        except OpenSearchCmdError as e:
            # This message means there was no "ca" alias or store before, if it happens ignore
            if f"Alias <{alias}> does not exist" in e.out:
                return

        old_ca_content = self.read_stored_ca(cert_type=cert_type, old=True)

        run_cmd(
            f"""{self.keytool} \
            -delete \
            -keystore {ca_trust_store} \
            -storepass {store_pwd} \
            -alias {alias} \
            -storetype PKCS12"""
        )
        logger.info(f"Removed {alias} from truststore.")
        # remove it from the request bundle
        if old_ca_content:
            self._remove_ca_from_request_bundle(old_ca_content, cert_type)

    def update_request_ca_bundle(self, cert_type: CertType) -> None:
        """Create a new chain.pem file for requests module"""
        logger.debug("Updating requests TLS CA bundle")
        if cert_type == CertType.APP_ADMIN:
            secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        else:
            secrets = self.charm.secrets.get_object(Scope.UNIT, cert_type, peek=True)

        # we store the pem format to make it easier for the python requests lib
        self.charm.opensearch.write_file(
            f"{self.certs_path}/{cert_type.val}-chain.pem",
            secrets["chain"],
        )

    def store_new_tls_resources(self, cert_type: CertType, secrets: Dict[str, Any]) -> bool:
        """Add key and cert to keystore."""
        if not self.ca_rotation_complete_in_cluster(cert_type):
            return False

        cert_name = cert_type.val
        store_path = f"{self.certs_path}/{cert_type}.p12"

        # if the TLS certificate is available before the keystore-password, create it anyway
        if cert_type == CertType.APP_ADMIN:
            self._create_keystore_pwd_if_not_exists(Scope.APP, cert_type, cert_type.val)
        else:
            self._create_keystore_pwd_if_not_exists(Scope.UNIT, cert_type, cert_type.val)

        if not secrets.get("key"):
            logging.error("TLS key not found, quitting.")
            return False

        try:
            os.remove(store_path)
        except OSError:
            pass

        tmp_key = tempfile.NamedTemporaryFile(
            mode="w+t", suffix=".pem", dir=self.charm.opensearch.paths.conf
        )
        tmp_key.write(secrets.get("key"))
        tmp_key.flush()
        tmp_key.seek(0)

        tmp_cert = tempfile.NamedTemporaryFile(
            mode="w+t", suffix=".cert", dir=self.charm.opensearch.paths.conf
        )
        tmp_cert.write(secrets.get("cert"))
        tmp_cert.flush()
        tmp_cert.seek(0)

        try:
            cmd = f"""openssl pkcs12 -export \
                -in {tmp_cert.name} \
                -inkey {tmp_key.name} \
                -out {store_path} \
                -name {cert_name}
            """
            args = f"-passout pass:{secrets.get('keystore-password')}"
            if secrets.get("key-password"):
                args = f"{args} -passin pass:{secrets.get('key-password')}"

            run_cmd(cmd, args)
            run_cmd(f"sudo chmod +r {store_path}")
        except OpenSearchCmdError as e:
            logging.error(f"Error storing the TLS certificates for {cert_name}: {e}")
        finally:
            tmp_key.close()
            tmp_cert.close()
            logger.info(f"TLS certificate for {cert_name} stored.")

        return True

    def all_tls_resources_stored(self, only_unit_resources: bool = False) -> bool:  # noqa: C901
        """Check if all TLS resources are stored on disk."""
        cert_types = [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        for cert_type in cert_types:
            # compare issuer of the cert with the issuer of the CA
            # if they don't match, certs are not up-to-date and need to be renewed after CA rotation
            if not (current_ca := self.read_stored_ca(cert_type=cert_type)):
                return False
            
            old_ca = self.read_stored_ca(cert_type=cert_type, old=True)
            if old_ca:
                tmp_old_ca_file = tempfile.NamedTemporaryFile(mode="w+t", dir=self.charm.opensearch.paths.conf)
                tmp_old_ca_file.write(old_ca)
                tmp_old_ca_file.flush()
                tmp_old_ca_file.seek(0)

            # to make sure the content is processed correctly by openssl, temporary store it in a file
            tmp_ca_file = tempfile.NamedTemporaryFile(mode="w+t", dir=self.charm.opensearch.paths.conf)
            tmp_ca_file.write(current_ca)
            tmp_ca_file.flush()
            tmp_ca_file.seek(0)

            try:
                old_ca_issuer = None
                ca_issuer = run_cmd(f"openssl x509 -in {tmp_ca_file.name} -noout -issuer").out
                if old_ca:
                    old_ca_issuer = run_cmd(f"openssl x509 -in {tmp_old_ca_file.name} -noout -issuer").out
            except OpenSearchCmdError as e:
                logger.error(f"Error reading the current truststore: {e}")
                return False
            finally:
                tmp_ca_file.close()

            if not exists(f"{self.certs_path}/{cert_type}.p12"):
                return False

            scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
            secret = self.charm.secrets.get_object(scope, cert_type.val, peek=True)

            try:
                cert_issuer = run_cmd(
                    f"openssl pkcs12 -in {self.certs_path}/{cert_type}.p12",
                    f"""-nodes \
                    -passin pass:{secret.get('keystore-password')} \
                    | openssl x509 -noout -issuer
                    """,
                ).out
            except OpenSearchCmdError as e:
                logger.error(f"Error reading the current certificate: {e}")
                return False
            except AttributeError as e:
                logger.error(f"Error reading secret: {e}")
                return False

            if cert_issuer != ca_issuer and cert_issuer != old_ca_issuer:
                return False

        return True

    def all_certificates_available(self) -> bool:
        """Method that checks if all certs available and issued from same CA."""
        secrets = self.charm.secrets

        admin_secrets = secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if not admin_secrets or not admin_secrets.get("cert"):
            return False

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val, peek=True)
            if not unit_secrets or not unit_secrets.get("cert"):
                return False

        return True

    def is_fully_configured(self) -> bool:
        """Check if all TLS secrets and resources exist and are stored."""
        return self.all_certificates_available() and self.all_tls_resources_stored()

    def is_fully_configured_in_cluster(self) -> bool:
        """Check if TLS is configured in all the units of the current cluster."""
        rel = self.model.get_relation(PeerRelationName)
        for unit in all_units(self.charm):
            for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT, CertType.APP_ADMIN]:
                if rel.data[unit].get(f"{cert_type.val}_tls_configured") != "True":
                    return False
        return True

    def store_admin_tls_secrets_if_applies(self) -> None:
        """Store admin TLS resources if available and mark unit as configured if correct."""
        # In the case of the first units before TLS is initialized,
        # or non-main orchestrator units having not received the secrets from the main yet
        if self.charm.unit.is_leader():
            return

        if not (
            current_secrets := self.charm.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
        ):
            return

        # in the case the cluster was bootstrapped with multiple units at the same time
        # and the certificates have not been generated yet
        if not current_secrets.get("cert") or not current_secrets.get("chain") or not current_secrets.get("ca-cert"):
            return

        # Store the "Admin" certificate, key and CA on the disk of the new unit
        self.store_new_tls_resources(CertType.APP_ADMIN, current_secrets)
        current_stored_ca = self.read_stored_ca(cert_type=CertType.APP_ADMIN, old=False)
        if current_stored_ca != current_secrets.get("ca-cert"):
            self.store_new_ca(current_secrets, CertType.APP_ADMIN)

        # Mark this unit as tls configured
        if self.is_fully_configured():
            self.charm.peers_data.put(Scope.UNIT, f"{CertType.APP_ADMIN.val}_tls_configured", True)

    def delete_stored_tls_resources(self):
        """Delete the TLS resources of the unit that are stored on disk."""
        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            try:
                os.remove(f"{self.certs_path}/{cert_type}.p12")
            except OSError:
                # thrown if file not exists, ignore
                pass

    def reload_tls_certificates(self):
        """Reload transport and HTTP layer communication certificates via REST APIs."""
        url_http = "_plugins/_security/api/ssl/http/reloadcerts"
        url_transport = "_plugins/_security/api/ssl/transport/reloadcerts"

        # using the SSL API requires authentication with app-admin cert and key
        admin_secret = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)

        tmp_cert = tempfile.NamedTemporaryFile(mode="w+t", dir=self.charm.opensearch.paths.conf)
        tmp_cert.write(admin_secret["cert"])
        tmp_cert.flush()
        tmp_cert.seek(0)

        tmp_key = tempfile.NamedTemporaryFile(mode="w+t", dir=self.charm.opensearch.paths.conf)
        tmp_key.write(admin_secret["key"])
        tmp_key.flush()
        tmp_key.seek(0)

        try:
            self.charm.opensearch.request(
                "PUT",
                url_http,
                cert_files=(tmp_cert.name, tmp_key.name),
                retries=3,
            )
            self.charm.opensearch.request(
                "PUT",
                url_transport,
                cert_files=(tmp_cert.name, tmp_key.name),
                retries=3,
            )
        except OpenSearchHttpError as e:
            logger.error(f"Error reloading TLS certificates via API: {e}")
            raise
        finally:
            tmp_cert.close()
            tmp_key.close()

    def _reset_ca_type_in_rotation_state(self) -> None:
        """Reset the CA type in rotation state."""
        self.charm.peers_data.delete(Scope.UNIT, CertType.APP_ADMIN.val)
        self.charm.peers_data.delete(Scope.UNIT, CertType.UNIT_TRANSPORT.val)
        self.charm.peers_data.delete(Scope.UNIT, CertType.UNIT_HTTP.val)
        self.update_ca_rotation_flag_to_peer_cluster_relation(
            flag=CertType.APP_ADMIN.val, operation="remove"
        )
        self.update_ca_rotation_flag_to_peer_cluster_relation(
            flag=CertType.UNIT_TRANSPORT.val, operation="remove"
        )
        self.update_ca_rotation_flag_to_peer_cluster_relation(
            flag=CertType.UNIT_HTTP.val, operation="remove"
        )

    def reset_ca_rotation_state(self) -> None:
        """Handle internal flags during CA rotation routine."""
        for cert_type in [CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT, CertType.APP_ADMIN]:
            if not self.charm.peers_data.get(Scope.UNIT, f"{cert_type.val}_tls_ca_renewing", False):
                # if the CA is not being renewed we don't have to do anything here
                return

            # if this flag is set, the CA rotation routine is complete for this unit
            if self.charm.peers_data.get(Scope.UNIT, f"{cert_type.val}_tls_ca_renewed", False):
                self.charm.peers_data.delete(Scope.UNIT, f"{cert_type.val}_tls_ca_renewing")
                self.charm.peers_data.delete(Scope.UNIT, f"{cert_type.val}_tls_ca_renewed")
                self._reset_ca_type_in_rotation_state()
                self.update_ca_rotation_flag_to_peer_cluster_relation(
                    flag=f"{cert_type.val}_tls_ca_renewing", operation="remove"
                )
                self.update_ca_rotation_flag_to_peer_cluster_relation(
                    flag=f"{cert_type.val}_tls_ca_renewed", operation="remove"
                )
            else:
                # this means only the CA rotation completed, still need to create certificates
                self.charm.peers_data.put(Scope.UNIT, f"{cert_type.val}_tls_ca_renewed", True)
                self.update_ca_rotation_flag_to_peer_cluster_relation(
                    flag=f"{cert_type.val}_tls_ca_renewed", operation="add"
                )

    def ca_rotation_complete_in_cluster(self, cert_type: CertType) -> bool:
        """Check whether the CA rotation completed in all units.
        
        If cert-type is not provided checks for any of the CAs."""
        rotation_happening = False
        rotation_complete = True
        for relation_type in [
            PeerRelationName,
            PeerClusterRelationName,
            PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                for unit in relation.units:
                    if relation.data[unit].get(f"{cert_type.val}_tls_ca_renewing") and not relation.data[unit].get(f"{cert_type.val}_tls_ca_renewed"):
                        rotation_happening = True

                    if not relation.data[unit].get(f"{cert_type.val}_tls_ca_renewed") and not relation.data[unit].get(f"{cert_type.val}_tls_configured", False):
                        logger.debug(
                            f"TLS CA rotation ongoing in unit {unit}, will not update tls certificates."
                        )
                        rotation_complete = False

        # if no unit is renewing the CA, or all of them renewed it, the rotation is complete
        return not rotation_happening or rotation_complete

    def ca_and_certs_rotation_complete_in_cluster(self, cert_type: CertType = None) -> bool:
        """Check whether the CA rotation completed in all units.

        If cert-type is not provided checks for any of the CAs."""
        rotation_complete = True

            # the current unit is not in the relation.units list
            # if (
            #     self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewing")
            #     or self.charm.peers_data.get(
            #         Scope.UNIT,
            #         "tls_ca_renewed",
            #     )
            #     or self.charm.peers_data.get(Scope.UNIT, "tls_configured") is not True
            # ):
            #     logger.debug("TLS CA rotation ongoing on this unit.")
            #     return False

        for relation_type in [
            PeerRelationName,
            PeerClusterRelationName,
            PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                logger.debug(f"Checking relation {relation}: units: {relation.units}")
                for unit in relation.units:
                    if (
                        f"{cert_type.val}_tls_ca_renewing" in relation.data[unit]
                        or f"{cert_type.val}_tls_ca_renewed" in relation.data[unit]
                        or relation.data[unit].get(f"{cert_type.val}_tls_configured") != "True"
                    ):
                        logger.debug(
                            f"TLS CA rotation not complete for unit {unit}: {relation} \
                                | {cert_type.val} tls_ca_renewing: {relation.data[unit].get(f'{cert_type.val}_tls_ca_renewing')} \
                                | {cert_type.val} tls_ca_renewed: {relation.data[unit].get(f'{cert_type.val}_tls_ca_renewed')} \
                                | {cert_type.val} tls_configured: {relation.data[unit].get(f'{cert_type.val}_tls_configured')}"
                        )
                        rotation_complete = False
                        break
        return rotation_complete

    def update_ca_rotation_flag_to_peer_cluster_relation(self, flag: str, operation: str) -> None:
        """Add or remove a CA rotation flag to all related peer clusters in large deployments."""
        for relation_type in [PeerClusterRelationName, PeerClusterOrchestratorRelationName]:
            for relation in self.model.relations[relation_type]:
                if operation == "add":
                    relation.data[self.charm.unit][flag] = "True"
                elif operation == "remove":
                    relation.data[self.charm.unit].pop(flag, None)

    def on_ca_certs_rotation_complete(self, cert_type: CertType) -> None:
        """Handle the completion of CA rotation."""
        logger.info("CA rotation completed. Deleting old CA and updating request bundle.")
        try:
            self.remove_old_ca(cert_type)
        except Exception as e:
            logger.error(f"Error removing old CA: {e}")
        self.update_request_ca_bundle(cert_type)

    def _add_ca_to_request_bundle(self, ca_cert: str, cert_type: CertType) -> None:
        """Add the CA cert to the request bundle for the requests module."""
        bundle_path = Path(self.certs_path) / f"{cert_type.val}-chain.pem"
        if not bundle_path.exists():
            return

        bundle_content = bundle_path.read_text()
        if ca_cert not in bundle_content:
            bundle_path.write_text(f"{bundle_content}\n{ca_cert}")

    def _remove_ca_from_request_bundle(self, ca_cert: str, cert_type: CertType) -> None:
        """Remove the CA cert from the request bundle for the requests module."""
        bundle_path = Path(self.certs_path) / f"{cert_type.val}-chain.pem"
        if not bundle_path.exists():
            return

        bundle_content = bundle_path.read_text()
        bundle_path.write_text(bundle_content.replace(ca_cert, ""))

    def old_ca_stored(self) -> bool:
        """Check if the old CA is stored."""
        for cert_type in [CertType.APP_ADMIN, CertType.UNIT_HTTP, CertType.UNIT_TRANSPORT]:
            if self.read_stored_ca(cert_type=cert_type, old=True) is not None:
                return True
        return False
