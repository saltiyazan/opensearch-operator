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
    TLS_RELATION,
    TLS_RELATION_ADMIN,
    TLS_RELATION_CLIENT,
    TLS_RELATION_PEER,
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
    Mode,
    PrivateKey,
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

        self.certs_peer = TLSCertificatesRequiresV4(
            charm,
            TLS_RELATION_PEER,
            certificate_requests=self._get_unit_certificate_requests(CertType.UNIT_TRANSPORT),
            private_key=self._get_private_key(CertType.UNIT_TRANSPORT)
        )
        self.certs_client = TLSCertificatesRequiresV4(
            charm,
            TLS_RELATION_CLIENT,
            certificate_requests=self._get_unit_certificate_requests(CertType.UNIT_HTTP),
            private_key=self._get_private_key(CertType.UNIT_HTTP)
        )
        self.certs_admin = TLSCertificatesRequiresV4(
            charm,
            TLS_RELATION_ADMIN,
            certificate_requests=self._get_admin_certificate_requests(),
            mode=Mode.APP,
            private_key=self._get_private_key(CertType.APP_ADMIN)
        )

        self.framework.observe(
            self.charm.on.set_tls_private_key_action, self._on_set_tls_private_key
        )

        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_created, self._on_tls_relation_created
        )
        self.framework.observe(
            self.charm.on[TLS_RELATION].relation_broken, self._on_tls_relation_broken
        )
        for cert_interface in [self.certs_admin, self.certs_peer, self.certs_client]:
            self.framework.observe(
                cert_interface.on.certificate_available,
                self._on_certificate_available
            )
        for relation_name in [TLS_RELATION_ADMIN, TLS_RELATION_PEER, TLS_RELATION_CLIENT]:
            self.framework.observe(
                self.charm.on[relation_name].relation_created,
                self._on_tls_relation_created
            )
            self.framework.observe(
                self.charm.on[relation_name].relation_broken,
                self._on_tls_relation_broken
            )

    def _get_admin_certificate_requests(self) -> List[CertificateRequestAttributes]:
        """Get the certificate requests for the admin certificate."""
        if not self.charm.unit.is_leader():
            logger.warning("Admin certificates are only available on the leader unit")
            return []
        return [
            CertificateRequestAttributes(
                common_name=self._get_subject(CertType.APP_ADMIN),
                organization=self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name,
                sans_oid=frozenset(self._get_sans(CertType.APP_ADMIN).get("sans_oid")),
            )
        ]

    def _get_unit_certificate_requests(self, cert_type: CertType) -> List[CertificateRequestAttributes]:
        sans = self._get_sans(cert_type)
        return [
            CertificateRequestAttributes(
                common_name=self._get_subject(cert_type),
                organization=self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name,
                sans_oid=frozenset(sans.get("sans_oid")),
                sans_dns=frozenset(sans.get("sans_dns")),
                sans_ip=frozenset(sans.get("sans_ip")),
            )
        ]

    def _get_private_key(self, cert_type: CertType) -> Optional[PrivateKey]:
        """Get the private key from secrets for the given cert type if it exists."""
        scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
        secrets = self.charm.secrets.get_object(scope, cert_type.val)

        if secrets and (key := secrets.get("key")):
            return PrivateKey.from_string(key)
        return None

    def _on_set_tls_private_key(self, event: ActionEvent) -> None:
        """Set the TLS private key, which will be used for requesting the certificate."""
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

        key = event.params.get("key")
        if key:
            self.charm.secrets.put_object(
                scope=scope,
                key=cert_type.val,
                value={"key": key},
                merge=True
            )
            if cert_type == CertType.APP_ADMIN:
                self.certs_admin.set_private_key(PrivateKey.from_string(key))
            elif cert_type == CertType.UNIT_TRANSPORT:
                self.certs_peer.set_private_key(PrivateKey.from_string(key))
            elif cert_type == CertType.UNIT_HTTP:
                self.certs_client.set_private_key(PrivateKey.from_string(key))
        else:
            if cert_type == CertType.APP_ADMIN:
                self.certs_admin.regenerate_private_key()
            elif cert_type == CertType.UNIT_TRANSPORT:
                self.certs_peer.regenerate_private_key()
            elif cert_type == CertType.UNIT_HTTP:
                self.certs_client.regenerate_private_key()

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
        admin_cert = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) or {}
        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            # create passwords for both ca trust_store/admin key_store
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, "ca")
            self._create_keystore_pwd_if_not_exists(
                Scope.APP, CertType.APP_ADMIN, CertType.APP_ADMIN.val
            )

        elif not admin_cert.get("truststore-password"):
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

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        """Enable TLS when TLS certificate available."""
        try:
            scope, cert_type, secrets = self._find_secret(str(event.certificate_signing_request), "csr")
            logger.debug(f"{scope.val}.{cert_type.val} TLS certificate available.")
            if not scope or not cert_type:
                for certs_admin_request_attr in self._get_admin_certificate_requests():
                    cert = self.certs_admin.get_assigned_certificate(certs_admin_request_attr)[0]
                    if cert and str(cert.certificate) == str(event.certificate):
                        scope = Scope.APP
                        cert_type = CertType.APP_ADMIN
                        break
                for certs_client_request_attr in self._get_unit_certificate_requests(CertType.UNIT_HTTP):
                    cert = self.certs_client.get_assigned_certificate(certs_client_request_attr)[0]
                    if cert and str(cert.certificate) == str(event.certificate):
                        scope = Scope.UNIT
                        cert_type = CertType.UNIT_HTTP
                        break
                for certs_transport_request_attr in self._get_unit_certificate_requests(CertType.UNIT_TRANSPORT):
                    cert = self.certs_peer.get_assigned_certificate(certs_transport_request_attr)[0]
                    if cert and str(cert.certificate) == str(event.certificate):
                        scope = Scope.UNIT
                        cert_type = CertType.UNIT_TRANSPORT
                        break
        except TypeError:
            logger.debug("Unknown certificate available.")
            return

        logger.debug(f"{scope.val}.{cert_type.val} TLS certificate available.")

        # Store CSR in secrets for future reference
        self.charm.secrets.put_object(
            scope,
            cert_type.val,
            {"csr": str(event.certificate_signing_request)},
            merge=True
        )

        # seems like the admin certificate is also broadcast to non leader units on refresh request
        if not self.charm.unit.is_leader() and scope == Scope.APP:
            return

        # Store latest cert/chain/CA in secrets
        ca_chain = "\n".join(str(cert) for cert in event.chain[::-1])
        current_secret_obj = self.charm.secrets.get_object(scope, cert_type.val) or {}
        secret = {
            "chain": current_secret_obj.get("chain"),
            "cert": current_secret_obj.get("cert"),
            "ca-cert": current_secret_obj.get("ca-cert"),
        }
        # Update the secret with the content from the event
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

        # Store CA in truststore with unique fingerprint-based alias
        if not self.store_new_ca(self.charm.secrets.get_object(scope, cert_type.val)):
            logger.debug("Could not store new CA certificate.")
            event.defer()
            return

        # Store the certificates and keys in a key store
        self.store_new_tls_resources(
            cert_type, self.charm.secrets.get_object(scope, cert_type.val)
        )

        # Always update the request bundle with the latest chain
        admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) or {}
        if admin_secrets.get("chain"):
            self.update_request_ca_bundle()

        # store the admin certificates in non-leader units
        # if admin cert not available we need to defer, otherwise it will never be stored
        if not self.charm.unit.is_leader():
            if admin_secrets.get("cert"):
                self.store_new_tls_resources(CertType.APP_ADMIN, admin_secrets)
            else:
                event.defer()
                return

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

        # Renewal is just a certificate change now
        renewal = (secret.get("cert") is not None and 
                  secret.get("cert") != str(event.certificate))

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

        dns = {self.charm.unit_name, socket.gethostname(), socket.getfqdn()}
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

    def _get_subject(self, cert_type: CertType) -> str:
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

        app_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if is_secret_found(app_secrets):
            return Scope.APP, CertType.APP_ADMIN, app_secrets

        u_transport_secrets = self.charm.secrets.get_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val
        )
        if is_secret_found(u_transport_secrets):
            return Scope.UNIT, CertType.UNIT_TRANSPORT, u_transport_secrets

        u_http_secrets = self.charm.secrets.get_object(Scope.UNIT, CertType.UNIT_HTTP.val)
        if is_secret_found(u_http_secrets):
            return Scope.UNIT, CertType.UNIT_HTTP, u_http_secrets

        return None

    def get_unit_certificates(self) -> Dict[CertType, str]:
        """Retrieve the list of certificates for this unit."""
        certs = {}
        if self.charm.unit.is_leader():
            admin_request = self._get_admin_certificate_requests()[0]
            admin_cert, _ = self.certs_admin.get_assigned_certificate(admin_request)
            certs[CertType.APP_ADMIN] = str(admin_cert.certificate)

        unit_transport_request = self._get_unit_certificate_requests(CertType.UNIT_TRANSPORT)[0]
        unit_transport_cert, _ = self.certs_peer.get_assigned_certificate(unit_transport_request)
        certs[CertType.UNIT_TRANSPORT] = str(unit_transport_cert.certificate)

        unit_http_request = self._get_unit_certificate_requests(CertType.UNIT_HTTP)[0]
        unit_http_cert, _ = self.certs_client.get_assigned_certificate(unit_http_request)
        certs[CertType.UNIT_HTTP] = str(unit_http_cert.certificate)

        return certs

    def _create_keystore_pwd_if_not_exists(self, scope: Scope, cert_type: CertType, alias: str):
        """Create passwords for the key stores if not already created."""
        store_pwd = None
        store_type = "truststore" if alias == "ca" else "keystore"

        secrets = self.charm.secrets.get_object(scope, cert_type.val)
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

    def store_new_ca(self, secrets: Dict[str, Any]) -> bool:
        """Add new CA cert to trust store.
        
        Each CA is stored with a unique alias based on its fingerprint to:
        - Ensure deterministic naming
        - Allow multiple valid CAs simultaneously
        - Enable tracking which CAs are in use
        """
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            return False

        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, "ca")

        admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) or {}

        if not ((secrets or {}).get("ca-cert") and admin_secrets.get("truststore-password")):
            logging.error("CA cert or truststore-password not found, quitting.")
            return False

        store_path = f"{self.certs_path}/ca.p12"

        # Create unique alias based on CA cert fingerprint
        with tempfile.NamedTemporaryFile(mode="w+t", dir=self.charm.opensearch.paths.conf) as ca_tmp_file:
            ca_tmp_file.write(secrets.get("ca-cert"))
            ca_tmp_file.flush()
            
            try:
                # Get CA fingerprint for unique alias
                fingerprint = run_cmd(
                    f"openssl x509 -noout -fingerprint -sha256 -in {ca_tmp_file.name}"
                ).out.split("=")[1].strip().replace(":", "")
                
                alias = f"ca-{fingerprint}"

                # Check if this CA is already in keystore
                try:
                    run_cmd(
                        f"{self.keytool} -list -alias {alias} -keystore {store_path} -storetype PKCS12",
                        f"-storepass {admin_secrets.get('truststore-password')}"
                    )
                    logger.info(f"CA {alias} already in truststore")
                    return True
                except OpenSearchCmdError:
                    # CA not found, proceed with import
                    pass

                # Import the new CA
                run_cmd(
                    f"""{self.keytool} -importcert \
                    -trustcacerts \
                    -noprompt \
                    -alias {alias} \
                    -keystore {store_path} \
                    -file {ca_tmp_file.name} \
                    -storetype PKCS12
                    """,
                    f"-storepass {admin_secrets.get('truststore-password')}",
                )
                run_cmd(f"sudo chmod +r {store_path}")
                logger.info(f"Added CA {alias} to truststore")

                # Only if we actually added a new CA (not if it was already there)
                added_new_ca = True

            except OpenSearchCmdError as e:
                logging.error(f"Error storing the ca-cert: {e}")
                return False

        # Only if we actually added a new CA (not if it was already there)
        if added_new_ca:
            self.charm.on_new_ca_added()
        
        return True

    def read_stored_ca(self, alias: str = "ca") -> Optional[str]:
        """Load stored CA cert."""
        secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)

        ca_trust_store = f"{self.certs_path}/ca.p12"
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
            if f"friendlyName: {alias}" in cert:
                return f"{start_cert_marker}{cert.split(start_cert_marker)[1]}{end_cert_marker}"

        return None

    def update_request_ca_bundle(self) -> None:
        """Create a new chain.pem file for requests module"""
        admin_secret = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)

        # we store the pem format to make it easier for the python requests lib
        self.charm.opensearch.write_file(
            f"{self.certs_path}/chain.pem",
            admin_secret["chain"],
        )

    def store_new_tls_resources(self, cert_type: CertType, secrets: Dict[str, Any]):
        """Add key and cert to keystore."""
        cert_name = cert_type.val
        store_path = f"{self.certs_path}/{cert_type}.p12"

        # if the TLS certificate is available before the keystore-password, create it anyway
        if cert_type == CertType.APP_ADMIN:
            self._create_keystore_pwd_if_not_exists(Scope.APP, cert_type, cert_type.val)
        else:
            self._create_keystore_pwd_if_not_exists(Scope.UNIT, cert_type, cert_type.val)

        if not secrets.get("key"):
            logging.error("TLS key not found, quitting.")
            return

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

    def all_tls_resources_stored(self, only_unit_resources: bool = False) -> bool:  # noqa: C901
        """Check if all TLS resources are stored on disk."""
        cert_types = [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]
        if not only_unit_resources:
            cert_types.append(CertType.APP_ADMIN)

        # compare issuer of the cert with the issuer of the CA
        # if they don't match, certs are not up-to-date and need to be renewed after CA rotation
        if not (current_ca := self.read_stored_ca()):
            return False

        # to make sure the content is processed correctly by openssl, temporary store it in a file
        tmp_ca_file = tempfile.NamedTemporaryFile(mode="w+t", dir=self.charm.opensearch.paths.conf)
        tmp_ca_file.write(current_ca)
        tmp_ca_file.flush()
        tmp_ca_file.seek(0)

        try:
            ca_issuer = run_cmd(f"openssl x509 -in {tmp_ca_file.name} -noout -issuer").out
        except OpenSearchCmdError as e:
            logger.error(f"Error reading the current truststore: {e}")
            return False
        finally:
            tmp_ca_file.close()

        for cert_type in cert_types:
            if not exists(f"{self.certs_path}/{cert_type}.p12"):
                return False

            scope = Scope.APP if cert_type == CertType.APP_ADMIN else Scope.UNIT
            secret = self.charm.secrets.get_object(scope, cert_type.val)

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

            if cert_issuer != ca_issuer:
                return False

        return True

    # TODO Yazan, I don't see where the CA is checked to be the same that issued the certificates
    def all_certificates_available(self) -> bool:
        """Method that checks if all certs available and issued from same CA."""
        secrets = self.charm.secrets

        admin_secrets = secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        if not admin_secrets or not admin_secrets.get("cert"):
            return False

        for cert_type in [CertType.UNIT_TRANSPORT, CertType.UNIT_HTTP]:
            unit_secrets = secrets.get_object(Scope.UNIT, cert_type.val)
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
            if rel.data[unit].get("tls_configured") != "True":
                return False
        return True

    def store_admin_tls_secrets_if_applies(self) -> None:
        """Store admin TLS resources if available and mark unit as configured if correct."""
        # In the case of the first units before TLS is initialized,
        # or non-main orchestrator units having not received the secrets from the main yet
        if not (
            current_secrets := self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)
        ):
            return

        # in the case the cluster was bootstrapped with multiple units at the same time
        # and the certificates have not been generated yet
        if not current_secrets.get("cert") or not current_secrets.get("chain"):
            return

        # Store the "Admin" certificate, key and CA on the disk of the new unit
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
        admin_secret = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val)

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
