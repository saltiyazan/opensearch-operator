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
from typing import Any, Dict, List, Optional, Tuple

from charms.opensearch.v0.constants_charm import (
    PeerClusterOrchestratorRelationName,
    PeerClusterRelationName,
    PeerRelationName,
)
from charms.opensearch.v0.constants_tls import (
    ADMIN_TLS_RELATION,
    CLIENT_TLS_RELATION,
    TRANSPORT_TLS_RELATION,
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


ADMIN_CA_ALIAS = "ca"
TRANSPORT_CA_ALIAS = "transport-ca"
HTTP_CA_ALIAS = "http-ca"

OLD_ADMIN_CA_ALIAS = f"old-{ADMIN_CA_ALIAS}"
OLD_TRANSPORT_CA_ALIAS = f"old-{TRANSPORT_CA_ALIAS}"
OLD_HTTP_CA_ALIAS = f"old-{HTTP_CA_ALIAS}"


logger = logging.getLogger(__name__)


class OpenSearchTLS(Object):
    """Class that Manages OpenSearch relation with TLS Certificates Operator."""

    def __init__(
        self, charm: "OpenSearchBaseCharm", peer_relation: str, jdk_path: str, certs_path: str
    ):
        super().__init__(charm, "tls-component")

        self.charm = charm
        self.jdk_path = jdk_path
        self.certs_path = certs_path
        self.peer_relation = peer_relation
        self.keytool = "opensearch.keytool"
        self.admin_certs = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=ADMIN_TLS_RELATION,
            certificate_requests=self._get_admin_certificate_requests(),
            mode=Mode.APP,
        )
        self.transport_certs = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=TRANSPORT_TLS_RELATION,
            certificate_requests=self._get_unit_certificate_requests(CertType.UNIT_TRANSPORT),
            mode=Mode.UNIT,
        )
        self.client_certs = TLSCertificatesRequiresV4(
            charm=self.charm,
            relationship_name=CLIENT_TLS_RELATION,
            certificate_requests=self._get_unit_certificate_requests(CertType.UNIT_HTTP),
            mode=Mode.UNIT,
        )

        self.framework.observe(
            self.charm.on.regenerate_tls_private_key_action, self._on_regenerate_tls_private_key
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

    def _get_admin_certificate_requests(self) -> List[CertificateRequestAttributes]:
        """Get the certificate requests for the admin certificate."""
        if not self.charm.unit.is_leader():
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
            )
        ]

    def _on_regenerate_tls_private_key(self, event: ActionEvent) -> None:
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
        if not self.charm.unit.is_leader():
            return
        certificate_attributes = self._get_admin_certificate_requests()[0]
        provider_certificate, _ = self.admin_certs.get_assigned_certificate(certificate_attributes)
        if provider_certificate:
            self.admin_certs.renew_certificate(provider_certificate)

    def request_new_unit_certificates(self) -> None:
        """Requests a new certificate with the given scope and type from the tls operator."""
        self.charm.peers_data.delete(Scope.UNIT, "tls_configured")

        for cert_type, cert_requirer in [
            (CertType.UNIT_HTTP, self.client_certs),
            (CertType.UNIT_TRANSPORT, self.transport_certs),
        ]:
            certificate_attributes = self._get_unit_certificate_requests(cert_type)[0]
            provider_certificate, _ = cert_requirer.get_assigned_certificate(
                certificate_attributes
            )
            if provider_certificate:
                cert_requirer.renew_certificate(provider_certificate)

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
        admin_secret = (
            self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            # create passwords for both ca trust_store/admin key_store
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, "ca")
            self._create_keystore_pwd_if_not_exists(
                Scope.APP, CertType.APP_ADMIN, CertType.APP_ADMIN.val
            )

        elif not admin_secret.get("truststore-password"):
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
        if certificate_attributes in self._get_admin_certificate_requests():
            scope = Scope.APP
            cert_type = CertType.APP_ADMIN
            _, pk = self.admin_certs.get_assigned_certificate(certificate_attributes)
            logger.info(
                "=====  Debugging the PR: Checking attributes in _on_certificate_available ====="
            )
            logger.info("attributes: %s", certificate_attributes)
            logger.info("scope: %s", scope)
            logger.info("cert_type: %s", cert_type)
            logger.info("=====  Debugging the PR =====")
        elif certificate_attributes in self._get_unit_certificate_requests(
            CertType.UNIT_TRANSPORT
        ):
            scope = Scope.UNIT
            cert_type = CertType.UNIT_TRANSPORT
            _, pk = self.transport_certs.get_assigned_certificate(certificate_attributes)
            logger.info(
                "=====  Debugging the PR: Checking attributes in _on_certificate_available ====="
            )
            logger.info("attributes: %s", certificate_attributes)
            logger.info("scope: %s", scope)
            logger.info("cert_type: %s", cert_type)
            logger.info("=====  Debugging the PR =====")
        elif certificate_attributes in self._get_unit_certificate_requests(CertType.UNIT_HTTP):
            scope = Scope.UNIT
            cert_type = CertType.UNIT_HTTP
            _, pk = self.client_certs.get_assigned_certificate(certificate_attributes)
            logger.info(
                "=====  Debugging the PR: Checking attributes in _on_certificate_available ====="
            )
            logger.info("attributes: %s", certificate_attributes)
            logger.info("scope: %s", scope)
            logger.info("cert_type: %s", cert_type)
            logger.info("=====  Debugging the PR =====")
        else:
            logger.debug("Unknown certificate available.")
            return
        admin_secrets = (
            self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        if scope != Scope.APP:
            # store the admin certificates in non-leader units
            # if admin cert not available we need to defer, otherwise it will never be stored
            if not admin_secrets.get("cert"):
                logger.info("Admin certificate not available yet. Waiting for next events.")
                event.defer()
                return

        logger.info("=====  Debugging the PR: Putting object in _on_certificate_available =====")
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
        logger.info("=====  Debugging the PR =====")
        logger.info("=====  Debugging the PR: Getting object in _on_certificate_available =====")
        secrets = self.charm.secrets.get_object(scope, cert_type.val, peek=True)
        logger.info("=====  Debugging the PR: Secrets: %s", secrets)
        logger.info("=====  Debugging the PR: Getting object in _on_certificate_available =====")

        # seems like the admin certificate is also broadcast to non leader units on refresh request
        if not self.charm.unit.is_leader() and scope == Scope.APP:
            return

        old_cert = secrets.get("cert", None)
        ca_chain = "\n".join(str(cert) for cert in event.chain[::-1])

        current_secret_obj = self.charm.secrets.get_object(scope, cert_type.val, peek=True) or {}
        secret = {
            "chain": current_secret_obj.get("chain"),
            "cert": current_secret_obj.get("cert"),
            "ca-cert": current_secret_obj.get("ca-cert"),
        }

        if secret != {"chain": ca_chain, "cert": str(event.certificate), "ca-cert": str(event.ca)}:
            # Juju is not able to check if secrets' content changed between revisions
            # this IF is intended to reduce a storm of secret-removed/-changed events
            # for the same content
            self.charm.secrets.put_object(
                scope,
                cert_type.val,
                {
                    "chain": ca_chain,
                    "cert": str(event.certificate),
                    "ca-cert": str(event.ca),
                },
                merge=True,
            )

        current_stored_ca = self.read_stored_ca(cert_type, old=False)
        if current_stored_ca != str(event.ca):  # what are we comparing here?
            if not self.store_new_ca(
                self.charm.secrets.get_object(scope, cert_type.val, peek=True), cert_type
            ):
                logger.info("=====  store_new_ca 1 =====")
                logger.debug("Could not store new CA certificate.")
                event.defer()
                return
            # replacing the current CA initiates a rolling restart and certificate renewal
            # the workflow is the following:
            # get new CA -> set tls_ca_renewing -> restart -> post_start_init -> set tls_ca_renewed
            # -> request new certs -> get new certs -> on_tls_conf_set
            # -> delete both tls_ca_renewing and tls_ca_renewed
            if current_stored_ca:
                logger.info("=====  store_new_ca 2 =====")
                self.charm.peers_data.put(Scope.UNIT, "tls_ca_renewing", True)
                self.update_ca_rotation_flag_to_peer_cluster_relation(
                    flag="tls_ca_renewing", operation="add"
                )
                logger.info("=====  store_new_ca 3 =====")
                self.charm.on_tls_ca_rotation()
                return

        # store the certificates and keys in a key store
        logger.info("=====  Calling store_new_tls_resources 1 =====")
        self.store_new_tls_resources(
            cert_type, self.charm.secrets.get_object(scope, cert_type.val, peek=True)
        )

        # apply the chain.pem file for API requests, only if the CA cert has not been updated
        if not self.charm.unit.is_leader():
            if admin_secrets.get("cert"):
                logger.info("=====  Calling store_new_tls_resources 2 =====")
                self.store_new_tls_resources(CertType.APP_ADMIN, admin_secrets)
        if admin_secrets.get("chain") and not self.read_stored_ca(
            cert_type=CertType.APP_ADMIN, old=True
        ):
            self.update_request_ca_bundle()

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

        dns = {self.charm.unit_name, socket.gethostname(), socket.getfqdn(), cert_type}
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
        """Get common name of the certificate."""
        if cert_type == CertType.APP_ADMIN:
            cn = "admin"
        else:
            cn = self.charm.unit_ip

        return cn

    def _get_subject(self, cert_type: CertType) -> str:
        """Get subject string for the certificate."""
        cluster_name = self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name
        common_name = self._get_common_name(cert_type)

        if cert_type == CertType.APP_ADMIN:
            sans = self._get_sans(cert_type)
            oid = sans["sans_oid"][0] if sans.get("sans_oid") else None
            if oid:
                return f"O={cluster_name},OID.2.5.4.45={oid},CN={common_name}"

        return f"O={cluster_name},CN={common_name}"

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
        logger.info("===== Store new CA 1 =====")
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            return False

        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            logger.info("===== Store new CA 2 =====")
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, "ca")

        admin_secrets = (
            self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True) or {}
        )
        logger.info("===== Store new CA 3 =====")
        if not ((secrets or {}).get("ca-cert") and admin_secrets.get("truststore-password")):
            logging.error("CA cert  or truststore-password not found, quitting.")
            return False
        logger.info("===== Store new CA 4 =====")

        # Select the appropriate CA alias based on cert type
        if cert_type == CertType.APP_ADMIN:
            ca_alias = ADMIN_CA_ALIAS
            old_ca_alias = OLD_ADMIN_CA_ALIAS
            logger.info("===== Store new CA 5 =====")
            logger.info(f"ca_alias: {ca_alias}")
        elif cert_type == CertType.UNIT_TRANSPORT:
            ca_alias = TRANSPORT_CA_ALIAS
            old_ca_alias = OLD_TRANSPORT_CA_ALIAS
            logger.info("===== Store new CA 6 =====")
            logger.info(f"ca_alias: {ca_alias}")
        elif cert_type == CertType.UNIT_HTTP:
            ca_alias = HTTP_CA_ALIAS
            old_ca_alias = OLD_HTTP_CA_ALIAS
            logger.info("===== Store new CA 7 =====")
            logger.info(f"ca_alias: {ca_alias}")
        else:
            logging.error(f"Unsupported certificate type: {cert_type}")
            return False

        store_path = f"{self.certs_path}/{ca_alias}.p12"

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
            logger.info(f"Current CA {ca_alias} was renamed to {old_ca_alias}.")
        except OpenSearchCmdError as e:
            # This message means there was no CA alias or store before, if it happens ignore
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

        self._add_ca_to_request_bundle(secrets.get("chain"))

        return True

    def read_stored_ca(
        self, cert_type: CertType = CertType.APP_ADMIN, old: bool = False
    ) -> Optional[str]:
        """Load stored CA cert.

        Args:
            cert_type: The type of certificate to read the CA for. Defaults to APP_ADMIN.
            old: Whether to read the old CA (during rotation) or current CA. Defaults to False.
        """
        secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)

        # Select the appropriate CA alias based on cert type
        if cert_type == CertType.APP_ADMIN:
            ca_alias = OLD_ADMIN_CA_ALIAS if old else ADMIN_CA_ALIAS
        elif cert_type == CertType.UNIT_TRANSPORT:
            ca_alias = OLD_TRANSPORT_CA_ALIAS if old else TRANSPORT_CA_ALIAS
        elif cert_type == CertType.UNIT_HTTP:
            ca_alias = OLD_HTTP_CA_ALIAS if old else HTTP_CA_ALIAS
        else:
            logging.error(f"Unsupported certificate type: {cert_type}")
            return None

        ca_trust_store = f"{self.certs_path}/{ADMIN_CA_ALIAS if cert_type == CertType.APP_ADMIN else ca_alias}.p12"
        if not (exists(ca_trust_store) and secrets):
            return None

        try:
            stored_certs = run_cmd(
                f"openssl pkcs12 -in {ca_trust_store}",
                f"-passin pass:{secrets.get('truststore-password')}",
            ).out
        except OpenSearchCmdError as e:
            logging.error(f"Error reading the current truststore: {e}")
            return None

        # parse output to retrieve the current CA (in case there are many)
        start_cert_marker = "-----BEGIN CERTIFICATE-----"
        end_cert_marker = "-----END CERTIFICATE-----"
        certificates = stored_certs.split(end_cert_marker)
        for cert in certificates:
            if f"friendlyName: {ca_alias}" in cert:
                return f"{start_cert_marker}{cert.split(start_cert_marker)[1]}{end_cert_marker}"

        return None

    def remove_old_ca(self, cert_type: CertType) -> None:
        """Remove old CA cert from trust store.

        Args:
            cert_type: The type of certificate whose old CA should be removed.
        """
        # Select the appropriate CA alias based on cert type
        if cert_type == CertType.APP_ADMIN:
            old_ca_alias = OLD_ADMIN_CA_ALIAS
            store_path = f"{self.certs_path}/{ADMIN_CA_ALIAS}.p12"
        elif cert_type == CertType.UNIT_TRANSPORT:
            old_ca_alias = OLD_TRANSPORT_CA_ALIAS
            store_path = f"{self.certs_path}/{TRANSPORT_CA_ALIAS}.p12"
        elif cert_type == CertType.UNIT_HTTP:
            old_ca_alias = OLD_HTTP_CA_ALIAS
            store_path = f"{self.certs_path}/{HTTP_CA_ALIAS}.p12"
        else:
            logging.error(f"Unsupported certificate type: {cert_type}")
            return

        secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        store_pwd = secrets.get("truststore-password")

        try:
            run_cmd(
                f"""{self.keytool} \
                -list \
                -keystore {store_path} \
                -storepass {store_pwd} \
                -alias {old_ca_alias} \
                -storetype PKCS12"""
            )
        except OpenSearchCmdError as e:
            # This message means there was no old CA alias or store, if it happens ignore
            if f"Alias <{old_ca_alias}> does not exist" in e.out:
                return

        old_ca_content = self.read_stored_ca(cert_type=cert_type, old=True)

        run_cmd(
            f"""{self.keytool} \
            -delete \
            -keystore {store_path} \
            -storepass {store_pwd} \
            -alias {old_ca_alias} \
            -storetype PKCS12"""
        )
        logger.info(f"Removed {old_ca_alias} from truststore.")
        # remove it from the request bundle
        if old_ca_content:
            self._remove_ca_from_request_bundle(old_ca_content)

    def update_request_ca_bundle(self) -> None:
        """Create a new chain.pem file for requests module"""
        admin_secret = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)

        # we store the pem format to make it easier for the python requests lib
        self.charm.opensearch.write_file(
            f"{self.certs_path}/chain.pem",
            admin_secret["chain"],
        )

    def store_new_tls_resources(self, cert_type: CertType, secrets: Dict[str, Any]):
        """Add key and cert to keystore."""
        logger.info("========== Store new TLS resources 1 ==========")
        if not self.ca_rotation_complete_in_cluster():
            return
        logger.info("========== Store new TLS resources 2 ==========")

        cert_name = cert_type.val
        store_path = f"{self.certs_path}/{cert_type}.p12"
        logger.info("========== Store new TLS resources 3 ==========")

        # if the TLS certificate is available before the keystore-password, create it anyway
        if cert_type == CertType.APP_ADMIN:
            self._create_keystore_pwd_if_not_exists(Scope.APP, cert_type, cert_type.val)
        else:
            self._create_keystore_pwd_if_not_exists(Scope.UNIT, cert_type, cert_type.val)
        logger.info("========== Store new TLS resources 4 ==========")
        if not secrets.get("key"):
            logging.error("TLS key not found, quitting.")
            return

        try:
            os.remove(store_path)
        except OSError:
            pass

        logger.info("========== Store new TLS resources 5 ==========")

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

        logger.info("========== Store new TLS resources 6 ==========")

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
            logger.info("========== Store new TLS resources 7 ==========")
        except OpenSearchCmdError as e:
            logging.error(f"Error storing the TLS certificates for {cert_name}: {e}")
        finally:
            tmp_key.close()
            tmp_cert.close()
            logger.info(f"TLS certificate for {cert_name} stored.")
            logger.info("========== Store new TLS resources 8 ==========")
        logger.info("========== Store new TLS resources 9 ==========")

    def all_tls_resources_stored(self, only_unit_resources: bool = False) -> bool:  # noqa: C901
        """Check if all TLS resources are stored on disk."""
        cert_types = [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        # compare issuer of the cert with the issuer of the CA
        # if they don't match, certs are not up-to-date and need to be renewed after CA rotation

        for cert_type in cert_types:
            if not exists(f"{self.certs_path}/{cert_type}.p12"):
                logger.info(
                    "=====  Debugging the PR, if we see this then tls is not yet fully configured 3 ====="
                )
                logger.info(f"cert_type: {cert_type}")
                logger.info("=====  Debugging the PR =====")
                return False

            scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
            secret = self.charm.secrets.get_object(scope, cert_type.val, peek=True)

            if not (current_ca := self.read_stored_ca(cert_type=cert_type)):
                logger.info(
                    "=====  Debugging the PR, if we see this then tls is not yet fully configured 1 ====="
                )
                logger.info(f"current_ca: {current_ca}")
                logger.info("=====  Debugging the PR =====")
                return False

            tmp_ca_file = tempfile.NamedTemporaryFile(
                mode="w+t", dir=self.charm.opensearch.paths.conf
            )
            tmp_ca_file.write(current_ca)
            tmp_ca_file.flush()
            tmp_ca_file.seek(0)

            try:
                ca_issuer = run_cmd(f"openssl x509 -in {tmp_ca_file.name} -noout -issuer").out
            except OpenSearchCmdError as e:
                logger.error(f"Error reading the current truststore: {e}")
                logger.info(
                    "=====  Debugging the PR, if we see this then tls is not yet fully configured 2 ====="
                )
                logger.info(f"Error reading the current truststore: {e}")
                logger.info("=====  Debugging the PR =====")
                return False
            finally:
                tmp_ca_file.close()

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
                logger.info(
                    "=====  Debugging the PR, if we see this then tls is not yet fully configured 4 ====="
                )
                logger.info(f"Error reading the current certificate: {e}")
                logger.info("=====  Debugging the PR =====")
                return False
            except AttributeError as e:
                logger.error(f"Error reading secret: {e}")
                logger.info(
                    "=====  Debugging the PR, if we see this then tls is not yet fully configured 5 ====="
                )
                logger.info(f"Error reading secret: {e}")
                logger.info("=====  Debugging the PR =====")
                return False

            if cert_issuer != ca_issuer:
                logger.info(
                    "=====  Debugging the PR, if we see this then tls is not yet fully configured 6 ====="
                )
                logger.info(f"cert_issuer: {cert_issuer}")
                logger.info(f"ca_issuer: {ca_issuer}")
                logger.info("=====  Debugging the PR =====")
                return False

        return True

    def all_certificates_available(self) -> bool:
        """Method that checks if all certs available and issued from same CA."""
        secrets = self.charm.secrets

        admin_secrets = secrets.get_object(Scope.APP, CertType.APP_ADMIN.val, peek=True)
        if not admin_secrets or not admin_secrets.get("cert"):
            logger.info(
                "=====  Debugging the PR, if we see this then tls is not yet fully configured 7 ====="
            )
            logger.info(f"admin_secrets: {admin_secrets}")
            logger.info("=====  Debugging the PR =====")
            return False

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val, peek=True)
            if not unit_secrets or not unit_secrets.get("cert"):
                logger.info(
                    "=====  Debugging the PR, if we see this then tls is not yet fully configured 8 ====="
                )
                logger.info(f"unit_secrets: {unit_secrets}")
                logger.info("=====  Debugging the PR =====")
                return False

        return True

    def is_fully_configured(self) -> bool:
        """Check if all TLS secrets and resources exist and are stored."""
        return self.all_certificates_available() and self.all_tls_resources_stored()

    def is_fully_configured_in_cluster(self) -> bool:
        """Check if TLS is configured in all the units of the current cluster."""
        rel = self.model.get_relation(PeerRelationName)
        for unit in all_units(self.charm):
            if rel.data[unit].get("tls_configured") != "True":
                return False
        return True

    def store_admin_tls_secrets_if_applies(self) -> None:
        """Store admin TLS resources if available and mark unit as configured if correct."""
        # In the case of the first units before TLS is initialized,
        # or non-main orchestrator units having not received the secrets from the main yet
        if not (
            current_secrets := self.charm.secrets.get_object(
                Scope.APP, CertType.APP_ADMIN.val, peek=True
            )
        ):
            return

        # in the case the cluster was bootstrapped with multiple units at the same time
        # and the certificates have not been generated yet
        if not current_secrets.get("cert") or not current_secrets.get("chain"):
            return

        # Store the "Admin" certificate, key and CA on the disk of the new unit
        logger.info("=====  Calling store_new_tls_resources 3 =====")
        self.store_new_tls_resources(CertType.APP_ADMIN, current_secrets)

        # Mark this unit as tls configured
        if self.is_fully_configured():
            self.charm.peers_data.put(Scope.UNIT, "tls_configured", True)

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

    def reset_ca_rotation_state(self) -> None:
        """Handle internal flags during CA rotation routine."""
        if not self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewing", False):
            # if the CA is not being renewed we don't have to do anything here
            return

        # if this flag is set, the CA rotation routine is complete for this unit
        if self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewed", False):
            self.charm.peers_data.delete(Scope.UNIT, "tls_ca_renewing")
            self.charm.peers_data.delete(Scope.UNIT, "tls_ca_renewed")
            self.update_ca_rotation_flag_to_peer_cluster_relation(
                flag="tls_ca_renewing", operation="remove"
            )
            self.update_ca_rotation_flag_to_peer_cluster_relation(
                flag="tls_ca_renewed", operation="remove"
            )
        else:
            # this means only the CA rotation completed, still need to create certificates
            self.charm.peers_data.put(Scope.UNIT, "tls_ca_renewed", True)
            self.update_ca_rotation_flag_to_peer_cluster_relation(
                flag="tls_ca_renewed", operation="add"
            )

    def ca_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_happening = False
        rotation_complete = True
        # check current unit
        if self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewing", False):
            logger.info("=====  ca_rotation_complete_in_cluster 1 =====")
            rotation_happening = True
        if not self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewed", False):
            logger.info("=====  ca_rotation_complete_in_cluster 2 =====")
            logger.debug(
                f"TLS CA rotation ongoing in unit: {self.charm.unit.name}, will not update tls certificates."
            )
            rotation_complete = False

        for relation_type in [
            PeerRelationName,
            PeerClusterRelationName,
            PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                for unit in relation.units:
                    if relation.data[unit].get("tls_ca_renewing"):
                        rotation_happening = True

                    if not relation.data[unit].get("tls_ca_renewed"):
                        logger.debug(
                            f"TLS CA rotation ongoing in unit {unit}, will not update tls certificates."
                        )
                        rotation_complete = False

        # if no unit is renewing the CA, or all of them renewed it, the rotation is complete
        return not rotation_happening or rotation_complete

    def ca_and_certs_rotation_complete_in_cluster(self) -> bool:
        """Check whether the CA rotation completed in all units."""
        rotation_complete = True

        # the current unit is not in the relation.units list
        if (
            self.charm.peers_data.get(Scope.UNIT, "tls_ca_renewing")
            or self.charm.peers_data.get(
                Scope.UNIT,
                "tls_ca_renewed",
            )
            or self.charm.peers_data.get(Scope.UNIT, "tls_configured") is not True
        ):
            logger.debug("TLS CA rotation ongoing on this unit.")
            return False

        for relation_type in [
            PeerRelationName,
            PeerClusterRelationName,
            PeerClusterOrchestratorRelationName,
        ]:
            for relation in self.model.relations[relation_type]:
                logger.debug(f"Checking relation {relation}: units: {relation.units}")
                for unit in relation.units:
                    if (
                        "tls_ca_renewing" in relation.data[unit]
                        or "tls_ca_renewed" in relation.data[unit]
                        or relation.data[unit].get("tls_configured") != "True"
                    ):
                        logger.debug(
                            f"TLS CA rotation not complete for unit {unit}: {relation} \
                                | tls_ca_renewing: {relation.data[unit].get('tls_ca_renewing')} \
                                | tls_ca_renewed: {relation.data[unit].get('tls_ca_renewed')} \
                                | tls_configured: {relation.data[unit].get('tls_configured')}"
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

    def on_ca_certs_rotation_complete(self) -> None:
        """Handle the completion of CA rotation."""
        logger.info("CA rotation completed. Deleting old CA and updating request bundle.")
        self.remove_all_old_cas()
        self.update_request_ca_bundle()

    def _add_ca_to_request_bundle(self, ca_cert: str) -> None:
        """Add the CA cert to the request bundle for the requests module."""
        bundle_path = Path(self.certs_path) / "chain.pem"
        if not bundle_path.exists():
            return

        bundle_content = bundle_path.read_text()
        if ca_cert not in bundle_content:
            bundle_path.write_text(f"{bundle_content}\n{ca_cert}")

    def _remove_ca_from_request_bundle(self, ca_cert: str) -> None:
        """Remove the CA cert from the request bundle for the requests module."""
        bundle_path = Path(self.certs_path) / "chain.pem"
        if not bundle_path.exists():
            return

        bundle_content = bundle_path.read_text()
        bundle_path.write_text(bundle_content.replace(ca_cert, ""))

    def has_any_old_ca(self) -> bool:
        """Check if there are any old CA certificates stored.

        Returns:
            bool: True if any old CA certificate exists, False otherwise.
        """
        for cert_type in [CertType.APP_ADMIN, CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            if self.read_stored_ca(cert_type=cert_type, old=True) is not None:
                return True
        return False

    def remove_all_old_cas(self) -> None:
        """Remove all old CA certificates from all trust stores."""
        for cert_type in [CertType.APP_ADMIN, CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            self.remove_old_ca(cert_type)
            logger.info(f"Completed old CA cleanup for {cert_type.val}")
