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

import logging
import os
import socket
import tempfile
import typing
from typing import Any, Dict, List, Tuple

from charms.opensearch.v0.helper_charm import run_cmd
from charms.opensearch.v0.helper_networking import get_host_public_ip
from charms.opensearch.v0.helper_security import generate_password
from charms.opensearch.v0.models import DeploymentType
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.tls_certificates_interface.v4.tls_certificates import (
    Certificate,
    CertificateAvailableEvent,
    CertificateRequestAttributes,
    Mode,
    PrivateKey,
    TLSCertificatesRequiresV4,
)
from ops.framework import Object

from charms.opensearch.v0.constants_tls import (
    ADMIN_TLS_RELATION,
    CLIENT_TLS_RELATION,
    TRANSPORT_TLS_RELATION,
    CertType,
)

if typing.TYPE_CHECKING:
    from charms.opensearch.v0.opensearch_base_charm import OpenSearchBaseCharm

from charms.opensearch.v0.opensearch_exceptions import (
    OpenSearchCmdError,
    OpenSearchError,
)

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
        self._ensure_keystores()
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
        for cert in [self.admin_certs, self.transport_certs, self.client_certs]:
            self.framework.observe(cert.on.certificate_available, self._on_certificate_available)

    def _get_admin_certificate_requests(self) -> List[CertificateRequestAttributes]:
        """Get the certificate requests for the admin certificate."""
        if not self.charm.unit.is_leader():
            logger.warning("Admin certificates are only available on the leader unit")
            return []
        if not self.charm.opensearch_peer_cm.deployment_desc():
            return []
        return [
            CertificateRequestAttributes(
                common_name="admin",
                organization=self.charm.opensearch_peer_cm.deployment_desc().config.cluster_name,
                sans_oid=frozenset(self._get_sans(CertType.APP_ADMIN).get("sans_oid")),
            )
        ]

    def _get_unit_certificate_requests(
        self, cert_type: CertType
    ) -> List[CertificateRequestAttributes]:
        if not self.charm.opensearch_peer_cm.deployment_desc():
            return []
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

    def _get_subject(self, cert_type: CertType) -> str:
        """Get subject of the certificate."""
        if cert_type == CertType.APP_ADMIN:
            cn = "admin"
        else:
            cn = self.charm.unit_ip

        return cn

    def _on_certificate_available(self, event: CertificateAvailableEvent) -> None:
        scope, cert_type = self._get_certificate_scope_and_type(str(event.certificate))
        self._ensure_keystores()
        if not self._store_ca(str(event.ca)):
            logger.warning("Could not store CA, deferring event")
            event.defer()
            return
        ca_chain = [str(chain) for chain in event.chain]
        if not self._store_ca_chain(ca_chain):
            logger.warning("Could not store CA Chain, deferring event")
            event.defer()
            return
        resources = {
            "ca": str(event.ca),
            "key": str(event.key),
            "cert": str(event.cert),
        }
        self._store_new_tls_resources(cert_type=cert_type, resources=resources)
        for relation in self.charm.opensearch_provider.relations:
            try:
                self.charm.opensearch_provider.update_certs(relation.id, ca_chain)
            except KeyError:
                # As we are setting the ca_chain, it should not be likely to happen a KeyError at
                # update_certs. This logic is left for a very corner case.
                logger.error("Error updating certificates in the relation: ca_chain not set.")
                event.defer()
                return

        # TODO, is the renewal = True here a terrible idea? I think whenever a new Cert is added (we are in the cert available event)
        # We should reload certs
        try:
            self.charm.on_tls_conf_set(event, scope, cert_type)
        except OpenSearchError as e:
            logger.exception(e)
            event.defer()

        self._clean_tls_resources()

    def _store_ca(self, ca_cert: str) -> bool:
        """Add new CA cert to trust store.

        Each CA is stored with a unique alias based on its fingerprint to:
        - Ensure deterministic naming
        - Allow multiple valid CAs simultaneously
        - Enable tracking which CAs are in use

        Returns:
            bool: True if a new CA was added, False if addition failed
        """
        if not self.charm.opensearch_peer_cm.deployment_desc():
            return False

        admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) or {}

        store_path = f"{self.certs_path}/ca.p12"

        # Create unique alias based on CA cert fingerprint
        with tempfile.NamedTemporaryFile(
            mode="w+t", dir=self.charm.opensearch.paths.conf
        ) as ca_tmp_file:
            ca_tmp_file.write(ca_cert)
            ca_tmp_file.flush()

            try:
                fingerprint = (
                    run_cmd(f"openssl x509 -noout -fingerprint -sha256 -in {ca_tmp_file.name}")
                    .out.split("=")[1]
                    .strip()
                    .replace(":", "")
                )

                alias = f"ca-{fingerprint}"

                # Try to import the CA - if it fails because alias exists, that's fine
                try:
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

                    # TODO
                    self.charm.on_new_ca_added()
                    return True

                except OpenSearchCmdError as e:
                    if "already exists" in str(e):
                        logger.info(f"CA {alias} already in truststore")
                        return False
                    logging.error(f"Error storing the ca-cert: {e}")
                    return False

            except OpenSearchCmdError as e:
                logging.error(f"Error processing the ca-cert: {e}")
                return False

    def _store_ca_chain(self, ca_chain: list) -> bool:
        """Add a list of CA certificates (chain) to the truststore.

        Each CA in the chain is stored with a unique alias based on its fingerprint.

        Args:
            ca_chain: A list of strings, where each string is a CA certificate
                    in PEM format.

        Returns:
            bool: True if all CAs in the chain were added successfully,
                False otherwise.
        """
        if not self.charm.opensearch_peer_cm.deployment_desc():
            return False

        admin_secrets = self.charm.secrets.get_object(Scope.APP, CertType.APP_ADMIN.val) or {}

        store_path = f"{self.certs_path}/ca.p12"

        all_added = True

        for ca_cert in ca_chain:
            with tempfile.NamedTemporaryFile(
                mode="w+t", dir=self.charm.opensearch.paths.conf
            ) as ca_tmp_file:
                ca_tmp_file.write(ca_cert)
                ca_tmp_file.flush()

                try:
                    fingerprint = (
                        run_cmd(f"openssl x509 -noout -fingerprint -sha256 -in {ca_tmp_file.name}")
                        .out.split("=")[1]
                        .strip()
                        .replace(":", "")
                    )

                    alias = f"ca-{fingerprint}"

                    try:
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
                        self.charm.on_new_ca_added()
                    except OpenSearchCmdError as e:
                        if "already exists" not in str(e):
                            all_added = False

                except OpenSearchCmdError as e:
                    all_added = False

        return all_added

    def _store_new_tls_resources(self, cert_type: CertType, resources: Dict[str, Any]) -> None:
        cert_name = cert_type.val
        store_path = f"{self.certs_path}/{cert_type}.p12"

        if not resources.get("key"):
            logging.error("TLS key not found, quitting.")
            return

        try:
            os.remove(store_path)
        except OSError:
            pass

        tmp_key = tempfile.NamedTemporaryFile(
            mode="w+t", suffix=".pem", dir=self.charm.opensearch.paths.conf
        )
        tmp_key.write(resources.get("key"))
        tmp_key.flush()
        tmp_key.seek(0)

        tmp_cert = tempfile.NamedTemporaryFile(
            mode="w+t", suffix=".cert", dir=self.charm.opensearch.paths.conf
        )
        tmp_cert.write(resources.get("cert"))
        tmp_cert.flush()
        tmp_cert.seek(0)

        try:
            cmd = f"""openssl pkcs12 -export \
                -in {tmp_cert.name} \
                -inkey {tmp_key.name} \
                -out {store_path} \
                -name {cert_name}
            """
            args = f"-passout pass:{resources.get('keystore-password')}"
            if resources.get("key-password"):
                args = f"{args} -passin pass:{resources.get('key-password')}"

            run_cmd(cmd, args)
            run_cmd(f"sudo chmod +r {store_path}")
        except OpenSearchCmdError as e:
            logging.error(f"Error storing the TLS certificates for {cert_name}: {e}")
        finally:
            tmp_key.close()
            tmp_cert.close()
            logger.info(f"TLS certificate for {cert_name} stored.")

    def _clean_tls_resources(self) -> None:
        # Go over all certs in keystore and truststore
        # Check if certificates are expired
        # If expired, remove from keystore and truststore
        pass

    def _get_certificate_scope_and_type(self, cert: str) -> Tuple[Scope, CertType]:
        """Get the scope and type of a certificate."""
        # Check admin cert
        request_attrs = self._get_admin_certificate_requests()
        provider_cert = self.admin_certs.get_assigned_certificate(request_attrs)[0]
        if provider_cert and str(provider_cert.certificate) == cert:
            return Scope.APP, CertType.APP_ADMIN

        request_attrs = self._get_unit_certificate_requests(CertType.UNIT_TRANSPORT)
        provider_cert = self.transport_certs.get_assigned_certificate(request_attrs)[0]
        if provider_cert and str(provider_cert.certificate) == cert:
            return Scope.UNIT, CertType.UNIT_TRANSPORT

        request_attrs = self._get_unit_certificate_requests(CertType.UNIT_HTTP)
        provider_cert = self.client_certs.get_assigned_certificate(request_attrs)[0]
        if provider_cert and str(provider_cert.certificate) == cert:
            return Scope.UNIT, CertType.UNIT_HTTP

        raise ValueError("Certificate not found in any scope/type")

    def _ensure_keystores(self) -> None:
        if not any(
            self._relation_created(rel)
            for rel in [ADMIN_TLS_RELATION, TRANSPORT_TLS_RELATION, CLIENT_TLS_RELATION]
        ):
            return
        if not (deployment_desc := self.charm.opensearch_peer_cm.deployment_desc()):
            return
        if self.charm.unit.is_leader() and deployment_desc.typ == DeploymentType.MAIN_ORCHESTRATOR:
            self._create_keystore_pwd_if_not_exists(Scope.APP, CertType.APP_ADMIN, "ca")
            self._create_keystore_pwd_if_not_exists(
                Scope.APP, CertType.APP_ADMIN, CertType.APP_ADMIN.val
            )
        self._create_keystore_pwd_if_not_exists(
            Scope.UNIT, CertType.UNIT_TRANSPORT, CertType.UNIT_TRANSPORT.val
        )
        self._create_keystore_pwd_if_not_exists(
            Scope.UNIT, CertType.UNIT_HTTP, CertType.UNIT_HTTP.val
        )

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

    def _relation_created(self, relation_name: str) -> bool:
        return bool(self.model.relations.get(relation_name))

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
