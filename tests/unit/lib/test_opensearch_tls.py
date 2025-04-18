# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import itertools
import re
import socket
import unittest
from unittest.mock import MagicMock, Mock, patch

import responses
from charms.opensearch.v0.constants_charm import (
    PeerRelationName,
    TLSCaRotation,
    TLSNotFullyConfigured,
)
from charms.opensearch.v0.constants_tls import (
    ADMIN_TLS_RELATION,
    CLIENT_TLS_RELATION,
    TRANSPORT_TLS_RELATION,
    CertType,
)
from charms.opensearch.v0.helper_conf_setter import YamlConfigSetter
from charms.opensearch.v0.models import (
    App,
    DeploymentDescription,
    DeploymentState,
    DeploymentType,
    Directive,
    PeerClusterConfig,
    StartMode,
    State,
)
from charms.opensearch.v0.opensearch_internal_data import Scope
from charms.tls_certificates_interface.v4.tls_certificates import PrivateKey
from ops.model import ActiveStatus, MaintenanceStatus
from ops.testing import Harness
from parameterized import parameterized

from charm import OpenSearchOperatorCharm
from tests.helpers import create_utf8_encoded_private_key
from tests.unit.helpers import (
    mock_response_health_green,
    mock_response_lock_not_requested,
    mock_response_nodes,
    mock_response_put_http_cert,
    mock_response_put_transport_cert,
    mock_response_root,
)


def single_space(input: str) -> str:
    """Replace multiple spaces with one."""
    return " ".join(input.split())


class TestOpenSearchTLS(unittest.TestCase):
    BASE_LIB_PATH = "charms.opensearch.v0"
    BASE_CHARM_CLASS = f"{BASE_LIB_PATH}.opensearch_base_charm.OpenSearchBaseCharm"
    PEER_CLUSTERS_MANAGER = (
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager"
    )

    deployment_descriptions = {
        "ok": DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.ACTIVE),
        ),
        "ko": DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="logs", init_hold=True, roles=["ml"], profile="production"
            ),
            start=StartMode.WITH_PROVIDED_ROLES,
            pending_directives=[Directive.WAIT_FOR_PEER_CLUSTER_RELATION],
            typ=DeploymentType.OTHER,
            app=App(model_uuid="model-uuid", name="opensearch"),
            state=DeploymentState(value=State.BLOCKED_CANNOT_START_WITH_ROLES, message="error"),
        ),
    }

    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def setUp(self, _) -> None:
        self.harness = Harness(OpenSearchOperatorCharm)
        self.harness.add_network("1.1.1.1")
        self.addCleanup(self.harness.cleanup)
        self.rel_id = self.harness.add_network("1.1.1.1", endpoint=PeerRelationName)

        self.harness.begin()
        self.charm = self.harness.charm

        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/0")

        self.harness.add_relation(ADMIN_TLS_RELATION, "tls-certificates")  # Add remote app name
        self.harness.add_relation(CLIENT_TLS_RELATION, "tls-certificates")
        self.harness.add_relation(TRANSPORT_TLS_RELATION, "tls-certificates")

        self.secret_store = self.charm.secrets

        socket.getfqdn = Mock()
        socket.getfqdn.return_value = "nebula"

        self.charm.opensearch.config = YamlConfigSetter(base_path="tests/unit/resources/config")

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.get_host_public_ip")
    @patch("socket.getfqdn")
    @patch("socket.gethostname")
    @patch("socket.gethostbyaddr")
    def test_get_sans(
        self, gethostbyaddr, gethostname, getfqdn, get_host_public_ip, deployment_desc
    ):
        """Test the SANs returned depending on the cert type."""
        deployment_desc.return_value = self.deployment_descriptions["ok"]

        self.assertDictEqual(
            self.charm.tls._get_sans(CertType.APP_ADMIN),
            {"sans_oid": ["1.2.3.4.5.5"]},
        )

        gethostbyaddr.return_value = (self.charm.unit_name, ["alias"], ["address1", "address2"])
        gethostname.return_value = "nebula"
        getfqdn.return_value = "nebula"
        get_host_public_ip.return_value = "XX.XXX.XX.XXX"

        base_ips = ["1.1.1.1", "address1", "address2"]
        base_dns_entries_http = [self.charm.unit_name, "nebula", "alias", CertType.UNIT_HTTP.val]
        base_dns_entries_transport = [self.charm.unit_name, "nebula", "alias", CertType.UNIT_TRANSPORT.val]

        unit_http_sans = self.charm.tls._get_sans(CertType.UNIT_HTTP)
        self.assertDictEqual(
            dict((key, sorted(val)) for key, val in unit_http_sans.items()),
            {
                "sans_oid": ["1.2.3.4.5.5"],
                "sans_ip": sorted(base_ips + ["XX.XXX.XX.XXX"]),
                "sans_dns": sorted(base_dns_entries_http),
            },
        )

        unit_transport_sans = self.charm.tls._get_sans(CertType.UNIT_TRANSPORT)
        self.assertDictEqual(
            dict((key, sorted(val)) for key, val in unit_transport_sans.items()),
            {
                "sans_oid": ["1.2.3.4.5.5"],
                "sans_ip": sorted(base_ips),
                "sans_dns": sorted(base_dns_entries_transport),
            },
        )

    def test_find_secret(self):
        """Test the secrets lookup depending on the event data."""
        event_data_cert = "cert_abcd12345"
        event_data_csr = "csr_abcd12345"

        self.assertIsNone(self.charm.tls._find_secret(event_data_cert, "cert"))
        self.assertIsNone(self.charm.tls._find_secret(event_data_csr, "csr"))

        self.secret_store.put_object(
            Scope.UNIT, CertType.UNIT_TRANSPORT.val, {"cert": event_data_cert}
        )
        self.secret_store.put_object(Scope.APP, CertType.APP_ADMIN.val, {"csr": event_data_csr})

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_relation_created_admin(self, _, __, deployment_desc):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        event_mock = MagicMock()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_tls_relation_created(event_mock)

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_relation_created_only_main_orchestrator_requests_application_cert(
        self, _, __, deployment_desc
    ):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.OTHER,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        # Truststore password is required
        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {"truststore-password": "abc"},
        )
        event_mock = MagicMock()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_tls_relation_created(event_mock)

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_relation_created_non_admin(self, _, __, deployment_desc):
        """Test on certificate relation created event."""
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        event_mock = MagicMock()

        truststore_password = "12345"
        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {"truststore-password": truststore_password},
        )

        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_tls_relation_created(event_mock)

    @patch("charm.OpenSearchOperatorCharm.on_tls_relation_broken")
    def test_on_relation_broken(self, on_tls_relation_broken):
        """Test on certificate relation broken event."""
        event_mock = MagicMock()
        self.charm.tls._on_tls_relation_broken(event_mock)

        on_tls_relation_broken.assert_called_once()

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.regenerate_private_key"
    )
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_regenerate_tls_private_key(self, _, __, _regenerate_private_key, deployment_desc):
        """Test _on_regenerate_tls_private_key event."""
        event_mock = MagicMock(params={"category": "app-admin"})

        self.harness.set_leader(is_leader=False)
        deployment_desc.return_value = self.deployment_descriptions["ko"]
        self.charm.tls._on_regenerate_tls_private_key(event_mock)
        _regenerate_private_key.assert_not_called()

        self.harness.set_leader(is_leader=True)
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        self.charm.tls._on_regenerate_tls_private_key(event_mock)
        _regenerate_private_key.assert_called_once()

        event_mock = MagicMock(params={"category": "unit-transport"})
        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_regenerate_tls_private_key(event_mock)
        _regenerate_private_key.assert_called()

    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("opensearch.OpenSearchSnap.write_file")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    def test_on_certificate_available_admin_cert(
        self,
        get_assigned_certificate,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        deployment_desc,
        on_tls_conf_set,
        store_new_ca,
        _,
        __,
        ___,
        _____,
    ):
        """Test _on_certificate_available event for the admin certificate."""
        org = "test-org"
        deployment_descriptions = {
            "ok": DeploymentDescription(
                config=PeerClusterConfig(
                    cluster_name=org, init_hold=False, roles=[], profile="production"
                ),
                start=StartMode.WITH_GENERATED_ROLES,
                pending_directives=[],
                typ=DeploymentType.MAIN_ORCHESTRATOR,
                app=App(model_uuid="model-uuid", name="opensearch"),
                state=DeploymentState(value=State.ACTIVE),
            ),
        }
        deployment_desc.return_value = deployment_descriptions["ok"]
        self.harness.set_leader(is_leader=True)
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_admin_certificate_requests()[0]
        )
        cert = "cert_12345"
        csr = "csr_12345"
        chain = ["chain_12345"]
        ca = "ca_12345"
        keystore_password = "keystore_12345"
        secret_key = CertType.APP_ADMIN.val

        self.secret_store.put_object(
            Scope.APP,
            secret_key,
            {"keystore-password": keystore_password},
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey("key"),
        )
        self.charm.tls._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.APP, secret_key),
            {
                "key": "key",
                "chain": chain[0],
                "cert": cert,
                "ca-cert": ca,
                "keystore-password": keystore_password,
                "csr": csr,
                "subject": f"/O={org}/CN={self.harness.charm.tls._get_admin_certificate_requests()[0].common_name}",
            },
        )

        store_new_ca.assert_called()
        on_tls_conf_set.assert_called()

    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    def test_on_certificate_available_unit_cert_admin_cert_not_available(
        self,
        deployment_desc,
        get_assigned_certificate,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        on_tls_conf_set,
        store_new_ca,
        _,
        __,
        ___,
    ):
        """Test _on_certificate_available event for the unit certificate.

        When the admin certificate is not available.
        """
        org = "test-org"
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_unit_certificate_requests(CertType.UNIT_TRANSPORT)[0]
        )
        cert = "cert_12345"
        chain = ["chain_12345"]
        ca = "ca_12345"
        csr = "csr_12345"
        keystore_password = "keystore_12345"
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(
            Scope.UNIT,
            secret_key,
            {"keystore-password": keystore_password},
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey("key"),
        )
        self.charm.tls._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, secret_key),
            {
                "keystore-password": keystore_password,
            },
        )

        store_new_ca.assert_not_called()
        on_tls_conf_set.assert_not_called()

    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    def test_on_certificate_available_unit_cert_admin_cert_available(
        self,
        deployment_desc,
        get_assigned_certificate,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        on_tls_conf_set,
        store_new_ca,
        _,
        __,
        ____,
    ):
        """Test _on_certificate_available event for the unit certificate.

        When the admin certificate is available.
        """
        org = "test-org"
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.MAIN_ORCHESTRATOR,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_unit_certificate_requests(CertType.UNIT_TRANSPORT)[0]
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey("key"),
        )
        cert = "cert_12345"
        chain = ["chain_12345"]
        ca = "ca_12345"
        csr = "csr_12345"
        keystore_password = "keystore_12345"
        secret_key = CertType.UNIT_TRANSPORT.val

        self.secret_store.put_object(
            Scope.UNIT,
            secret_key,
            {"keystore-password": keystore_password},
        )

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "cert": "random admin cert",
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )
        self.charm.tls._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, secret_key),
            {
                "key": "key",
                "chain": chain[0],
                "cert": cert,
                "ca-cert": ca,
                "keystore-password": keystore_password,
                "csr": csr,
                "subject": f"/O={org}/CN={self.harness.charm.tls._get_unit_certificate_requests(CertType.UNIT_TRANSPORT)[0].common_name}",
            },
        )

        store_new_ca.assert_called()
        on_tls_conf_set.assert_called()

    # Testing store_new_ca() function

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_truststore_password_secret(
        self, _, __, _create_keystore_pwd_if_not_exists, deployment_desc
    ):
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        secret = {"key": "secret_12345"}

        self.harness.set_leader(is_leader=False)
        self.charm.tls.store_new_ca(secret)

        _create_keystore_pwd_if_not_exists.assert_not_called()

        self.harness.set_leader(is_leader=True)
        self.charm.tls.store_new_ca(secret)

        _create_keystore_pwd_if_not_exists.assert_called_once()

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_truststore_password_secret_only_created_by_main_orchestrator(
        self, _, __, _create_keystore_pwd_if_not_exists, deployment_desc
    ):
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=DeploymentType.OTHER,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        secret = {"key": "secret_12345"}

        self.harness.set_leader(is_leader=True)
        self.charm.tls.store_new_ca(secret)

        _create_keystore_pwd_if_not_exists.assert_not_called()

    ##########################################################################
    # Full workflow tests
    ##########################################################################

    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_leader_app_cert_full_workflow(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        get_assigned_certificate,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        read_stored_ca,
        deployment_desc,
        run_cmd,
        named_temporary_file,
    ):
        """New certificate received.

        The charm leader unit should save the new certificate both to
        Juju secrets and to the keystore.

        Applies to:
         - all deployments
         - leader ONLY
        """
        org = "test-org"
        self.harness.set_leader(is_leader=True)
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_admin_certificate_requests()[0]
        )
        key = "key"
        ca = "ca"
        csr = "csr_12345"
        new_cert = "new_cert"
        new_chain = ["new_chain"]

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
            },
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey(key),
        )
        # Purposefully not adding unit certificates, to also trigger corner-case checks

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=new_chain, certificate=new_cert, ca=ca
        )

        # There was no change of the CA (certificate), the event matches the one on disk
        read_stored_ca.return_value = ca

        original_status_app = self.harness.model.app.status
        original_status_unit = self.harness.model.unit.status
        self.charm._restart_opensearch_event = MagicMock()

        self.charm.tls._on_certificate_available(event_mock)

        # The new cert is saved to the keystore
        # NOTE on the leader node, the operation is redundant i.e. executed TWICE
        # This is because the function that applies on normal units to save app certificate
        # is executed on top of the mechanism that recognizes that the leader
        # received a new app cert
        assert run_cmd.call_count == 4

        assert re.search(
            "openssl pkcs12 -export .*-out "
            "/var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12 .*-name app-admin",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            "sudo chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12"
            in run_cmd.call_args_list[1].args[0]
        )
        assert (
            "/var/snap/opensearch/current/etc/opensearch"
            in named_temporary_file.call_args_list[0][1]["dir"]
        )

        assert self.harness.model.app.status == original_status_app
        assert self.harness.model.unit.status == original_status_unit

        # The new certificate is now replacing the old one in Peer Relation secrets
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "key": key,
            "ca-cert": ca,
            "cert": new_cert,
            "chain": new_chain[0],
            "truststore-password": "truststore_12345",
            "keystore-password": "keystore_12345",
            "csr": csr,
            "subject": f"/O={org}/CN={self.harness.charm.tls._get_admin_certificate_requests()[0].common_name}",
        }

    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        itertools.product(
            [
                (DeploymentType.MAIN_ORCHESTRATOR),
                (DeploymentType.OTHER),
                (DeploymentType.FAILOVER_ORCHESTRATOR),
            ],
            [True, False],
            [CertType.UNIT_HTTP.val, CertType.UNIT_TRANSPORT.val],
        )
    )
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.get_host_public_ip")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_any_node_unit_cert_full_workflow(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        leader,
        cert_type,
        _,
        get_assigned_certificate,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        get_host_public_ip,
        read_stored_ca,
        deployment_desc,
        run_cmd,
        named_temporary_file,
    ):
        """New *unit* certificate received.

        At this point the charm leader unit should save the new certificate both to
        Juju secrets and to the keystore.

        Applies to:
         - all deployments
         - all units
        """
        get_host_public_ip.return_value = "10.1.146.1"
        org = "test-org"
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_unit_certificate_requests(cert_type)[0]
        )
        key = "key"
        ca = "ca"
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey(key),
        )
        keystore_password = "keystore_12345"

        new_cert = "new_cert"
        new_chain = ["new_chain"]

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT,
            {
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP,
            {
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=f"{cert_type}-csr",
            chain=new_chain,
            certificate=new_cert,
            ca=ca,
        )

        # There was no change of the CA (certificate), the event matches the one on disk
        read_stored_ca.return_value = ca

        self.harness.set_leader(is_leader=leader)

        original_status_unit = self.harness.model.unit.status
        self.charm._restart_opensearch_event = MagicMock()

        self.charm.tls._on_certificate_available(event_mock)

        # The new cert is saved to the keystore
        if self.charm.unit.is_leader():
            assert run_cmd.call_count == 2
        else:
            assert run_cmd.call_count == 4

        assert re.search(
            "openssl pkcs12 -export .*-out "
            f"/var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12 .*-name {cert_type}",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            f"sudo chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12"
            in run_cmd.call_args_list[1].args[0]
        )
        assert (
            "/var/snap/opensearch/current/etc/opensearch"
            in named_temporary_file.call_args_list[0][1]["dir"]
        )

        assert self.harness.model.unit.status == original_status_unit

        # The new certificate is now replacing the old one in Peer Relation secrets
        assert self.secret_store.get_object(Scope.UNIT, cert_type) == {
            "key": key,
            "ca-cert": ca,
            "csr": f"{cert_type}-csr",
            "cert": new_cert,
            "chain": new_chain[0],
            "keystore-password": keystore_password,
            "truststore-password": "truststore_12345",
            "subject": f"/O={org}/CN={self.harness.charm.tls._get_unit_certificate_requests(cert_type)[0].common_name}",
        }

    ##########################################################################
    # Tests below verify to the CA rotation cycle
    ##########################################################################

    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._add_ca_to_request_bundle")
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    # Mocks to avoid I/O
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_ca_rotation_first_stage_any_cluster_leader(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        get_assigned_certificate,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        deployment_desc,
        read_stored_ca,
        run_cmd,
        named_temporary_file,
        mock_add_ca_to_request_bundle,
    ):
        """Test CA rotation 1st stage.

        At this point the charm already is receiving a new CA cert from the
        'self-signed-certificates' charm.
        Note: there is no preceding action on any of the involved parties to trigger that.
        The new CA cert may be received due to a CA change, CA cert expiration, etc.
        The 'self-signed-certificates' operator sends no signal/notification but simply adds
        the new CA certificate to a 'certificate-available' event.

        On this event, the Opensearch charm should:
         - save the new CA cert to truststore ALONGSIDE the old one that receives a new alias
         - set the 'tls_ca_renewing' flag in the peer databag
         - trigger a service restart
         - set the charm state to 'maintenance', indicating CA certificate rotation

        NOTE: The 'certificate-available' event also contains a new cert and chain. These are
        kind of "useless", as will need to request new ones matching the new CA cert.
        Not to modify existing workflows, they are saved to the secret but NOT to the disk.
        (The inconsistency is temporary, while the charm is in a maintenance mode anyway.)

        Applies to
         - any deployment types
         - leader ONLY
           - normal units are passive, see test later
        """
        org = "test-org"
        self.harness.set_leader(is_leader=True)
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_admin_certificate_requests()[0]
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey("key"),
        )

        new_cert = "new_cert"
        new_chain = ["new_chain"]
        new_ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )

        # NOTE: The event is issued with the old csr, i.e. the identifier of
        # the ongoing transaction. A new csr will be generated and saved in the second step
        event_mock = MagicMock(
            certificate_signing_request="old_csr", chain=new_chain, certificate=new_cert, ca=new_ca
        )

        # The CA stored in the keystore is still the old one
        read_stored_ca.return_value = "old_ca"

        self.charm._restart_opensearch_event = MagicMock()

        original_status = self.harness.model.unit.status

        self.charm.tls._on_certificate_available(event_mock)

        mock_add_ca_to_request_bundle.assert_called_once()

        # Old CA cert is saved with corresponding alias, new new CA cert added to keystore
        assert run_cmd.call_count == 3
        assert re.search(
            "keytool *-changealias *-alias ca *-destalias old-ca",
            run_cmd.call_args_list[0].args[0],
        )
        assert re.search("keytool *-importcert.* *-alias ca", run_cmd.call_args_list[1].args[0])
        assert (
            "chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/ca.p12"
            in run_cmd.call_args_list[2].args[0]
        )
        assert (
            "/var/snap/opensearch/current/etc/opensearch"
            in named_temporary_file.call_args_list[0][1]["dir"]
        )
        # NOTE: The new cert and chain are NOT saved into the keystore (disk)

        # Set flag, set status, restart
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewing"]
            == "True"
        )
        assert isinstance(self.harness.model.unit.status, MaintenanceStatus)
        assert self.harness.model.unit.status.message == TLSCaRotation
        assert self.harness.model.unit.status, MaintenanceStatus != original_status
        self.charm._restart_opensearch_event.emit.assert_called_once()

        # The new certificate is now replacing the old one in Peer Relation secrets
        # NOTE: INCONSISTENCY: The new cert and chain ARE saved into the secret
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "key": "key",
            "cert": new_cert,
            "csr": "old_csr",
            "chain": new_chain[0],
            "truststore-password": "truststore_12345",
            "keystore-password": "keystore_12345",
            "ca-cert": new_ca,
            "subject": f"/O={org}/CN={self.harness.charm.tls._get_admin_certificate_requests()[0].common_name}",
        }

    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    def test_on_certificate_available_ca_rotation_first_stage_any_cluster_non_leader(
        # NOTE: Syntax: parametrized parameter comes first
        self,
        deployment_type,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        deployment_desc,
        read_stored_ca,
        run_cmd,
    ):
        """'certificate-available' with an app cert and/or a CA cert.

        ONLY the leader takes action.
        """
        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"
        csr = "csr_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )

        read_stored_ca.return_value = "stored_ca"

        # Applies to ANY deployment type
        org = "test-org"
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        self.harness.set_leader(is_leader=True)
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_admin_certificate_requests()[0]
        )

        self.harness.set_leader(is_leader=False)
        original_status = self.harness.model.unit.status
        self.charm._restart_opensearch_event = MagicMock()

        self.charm.tls._on_certificate_available(event_mock)

        # No action taken, no change on status or certificates
        assert run_cmd.call_count == 0
        assert self.harness.model.unit.status == original_status
        self.charm._restart_opensearch_event.emit.assert_not_called()
        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
            "ca-cert": "old_ca_cert",
            "cert": "old_cert",
        }

    # Mocks on functions we want to investigate
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Necessary mocks to simulate a smotth startup
    @patch("machine_upgrade.Upgrade")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("socket.socket.connect")
    @responses.activate
    def test_on_certificate_available_ca_rotation_second_stage_any_cluster_leader(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        __,
        upgrade,
        deployment_desc,
        read_stored_ca,
    ):
        """Test CA rotation 2nd stage.

        At this point the charm already has the new CA cert stored locally
        (with the old CA cert also being kept around) and a service restart
        was supposed to take place.

        After the restart
         - old certificates have to be renewed using the new CA cert
         - to signify the above being completed, the 'tls_ca_renewed' flag is set in the databag.

        Applies to
         - any deployment types
         - LEADER ONLY
        """
        # Units had their certificates already
        old_key = create_utf8_encoded_private_key()
        keystore_password = "keystore_12345"

        new_ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
                "ca-cert": new_ca,
                "key": old_key,
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT.val,
            {
                "keystore-password": keystore_password,
                "key": "key-transport",
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP.val,
            {"keystore-password": keystore_password, "key": "key-http"},
        )

        # Leader ONLY
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            self.harness.update_relation_data(
                self.rel_id, "opensearch", {"security_index_initialised": "True"}
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True"}
            )

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        upgrade_mock = MagicMock(app_status=ActiveStatus())
        upgrade_mock.get_unit_juju_status.return_value = ActiveStatus()
        upgrade.return_value = upgrade_mock

        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_lock_not_requested("1.1.1.1")
        mock_response_health_green("1.1.1.1")
        event = MagicMock(after_upgrade=False)
        original_status = self.harness.model.unit.status

        self.charm._post_start_init(event)

        # 'tls_ca_renewed' flag is set, new unit certificates were requested
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewed"] == "True"
        )

        new_app_admin_secret = self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val)

        assert new_app_admin_secret["ca-cert"] == new_ca
        assert new_app_admin_secret["key"] == old_key

        assert self.harness.model.unit.status.message == TLSNotFullyConfigured
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Mocks on functions we want to investigate
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    # Necessary mocks to simulate a smooth startup
    @patch("machine_upgrade.Upgrade")
    @patch("socket.socket.connect")
    @responses.activate
    def test_on_certificate_available_ca_rotation_second_stage_any_cluster_non_leader(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        upgrade,
        read_stored_ca,
        deployment_desc,
    ):
        """Test CA rotation 2nd stage.

        At this point the charm already has the new CA cert stored locally
        (with the old CA cert also being kept around) and a service restart
        was supposed to take place.

        After the restart, unit certificates have to be renewed,
        and the 'tls_ca_renewed' flag has to be set in the databag.

        Applies to
         - any deployment types
         - any units
        """
        # Units had their certificates already
        ca = "new_ca"
        keystore_password = "keystore_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "ca-cert": ca,
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT.val,
            {
                "keystore-password": keystore_password,
                "key": "key-transport",
            },
        )
        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP.val,
            {"keystore-password": keystore_password, "key": "key-http"},
        )

        # Emphasizing: NON-leader
        self.harness.set_leader(is_leader=False)
        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.rel_id, "opensearch", {"security_index_initialised": "True"}
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True"}
            )

        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        upgrade_mock = MagicMock(app_status=ActiveStatus())
        upgrade_mock.get_unit_juju_status.return_value = ActiveStatus()
        upgrade.return_value = upgrade_mock

        mock_response_root(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_nodes(self.charm.unit_name, self.charm.opensearch.host)
        mock_response_lock_not_requested("1.1.1.1")
        mock_response_health_green("1.1.1.1")
        event = MagicMock(after_upgrade=False)
        original_status = self.harness.model.unit.status

        self.charm._post_start_init(event)

        # 'tls_ca_renewed' flag is set, new unit certificates were requested
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewed"] == "True"
        )
        # Note that the old flag is left intact
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewing"]
            == "True"
        )

        assert self.harness.model.unit.status.message == TLSNotFullyConfigured
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Mocks to investigate/compare/alter
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_ca_rotation_third_stage_leader_cert_app(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        _,
        get_assigned_certificate,
        read_stored_ca,
        deployment_desc,
        run_cmd,
        named_temporary_file,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
    ):
        """Test CA rotation 3rd stage -- *app* certificate.

        At this point, the new CA has been already saved to the keystore.
        The charm receives the new app certificate. The leader unit has to save it.

        Applies to:

        """
        org = "test-org"
        self.harness.set_leader(is_leader=True)
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_admin_certificate_requests()[0]
        )
        cert = "new_cert"
        csr = "csr_12345"
        chain = ["new_chain"]
        ca = "new_ca"
        key = "key"
        keystore_password = "keystore_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "ca-cert": ca,
                "key": key,
            },
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey(key),
        )

        event_mock = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )

        # The new CA cert has been saved to the keystore earlier
        def mock_stored_ca(alias: str | None = None):
            if alias == "old-ca":
                return "old_ca_cert"
            return ca

        read_stored_ca.side_effect = mock_stored_ca

        self.charm._restart_opensearch_event = MagicMock()
        self.harness.model.unit.status = MaintenanceStatus()
        original_status = self.harness.model.unit.status

        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
            self.harness.update_relation_data(
                self.rel_id, "opensearch", {"security_index_initialised": "True"}
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True", "tls_ca_renewed": "True"}
            )

        self.charm.tls._on_certificate_available(event_mock)

        # NOTE: Currently store_new_tls_resources() is invoked twice for 'app-admin' cert!
        assert run_cmd.call_count == 4

        # Exporting new certs
        assert re.search(
            "openssl pkcs12 -export .* -out "
            "/var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12 .* -name app-admin",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            "chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/app-admin.p12"
            in run_cmd.call_args_list[1].args[0]
        )
        assert (
            "/var/snap/opensearch/current/etc/opensearch"
            in named_temporary_file.call_args_list[0][1]["dir"]
        )
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewed"] == "True"
        )
        # Note that the old flag is left intact
        assert (
            self.harness.get_relation_data(self.rel_id, "opensearch/0")["tls_ca_renewing"]
            == "True"
        )

        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "cert": cert,
            "chain": chain[0],
            "truststore-password": "truststore_12345",
            "keystore-password": "keystore_12345",
            "key": key,
            "ca-cert": ca,
            "csr": csr,
            "subject": f"/O={org}/CN={self.harness.charm.tls._get_admin_certificate_requests()[0].common_name}",
        }

        assert self.harness.model.unit.status.message == ""
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Mocks to investigate/compare/alter
    # NOTE: Syntax: parametrized has to be the outermost decorator
    @parameterized.expand(
        list(
            itertools.product(
                [
                    (DeploymentType.MAIN_ORCHESTRATOR),
                    (DeploymentType.OTHER),
                    (DeploymentType.FAILOVER_ORCHESTRATOR),
                ],
                [True, False],
                [CertType.UNIT_HTTP.val, CertType.UNIT_TRANSPORT.val],
            )
        )
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._remove_ca_from_request_bundle")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.reload_tls_certificates")
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.get_host_public_ip")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    # Mocks to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.exists", return_value=True)
    @patch("opensearch.OpenSearchSnap.write_file")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    @patch("socket.socket.connect")
    @responses.activate
    def test_on_certificate_available_ca_rotation_third_stage_any_unit_cert_unit(
        self,
        # NOTE: Syntax: parametrized parameter comes first
        deployment_type,
        leader,
        cert_type,
        _,
        __,
        ___,
        _____,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        get_host_public_ip,
        read_stored_ca,
        deployment_desc,
        run_cmd,
        named_temporary_file,
        reload_tls_certificates,
        mock_remove_ca_from_request_bundle,
    ):
        """Test CA rotation 3rd stage -- *unit* certificate.

        At this point, the new CA has been already saved to the keystore.
        The charm receives a new unit certificate in the 'certificate-available' event.
        The unit has to
         1. save the new certificate
         2. if it was the last one to be updated: remove CA renewal flags
         3. if it was the last one updated: remove CA from keystore

        Applies to:
         - all deployments
         - all units
        """
        get_host_public_ip.return_value = "10.1.146.1"
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name="", init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_unit_certificate_requests(cert_type)[0]
        )

        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"
        key = "key"
        keystore_password = "keystore_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": "new_csr",
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
                "ca-cert": ca,
                "cert": "cert",
                "key": "new_key",
                "subject": "new_subject",
                "chain": chain,
            },
        )

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT,
            {
                "csr": f"{CertType.UNIT_TRANSPORT.val}-csr-new",
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP,
            {
                "csr": f"{CertType.UNIT_HTTP.val}-csr-new",
                "truststore-password": "truststore_12345",
                "keystore-password": keystore_password,
                "key": key,
                "ca-cert": ca,
                "cert": "old_cert",
            },
        )

        # The event is addressing the transaction identified by the new csr
        # for the corresponding cert type defined by the test parameter
        event_mock = MagicMock(
            certificate_signing_request=f"{cert_type}-csr-new",
            chain=chain,
            certificate=cert,
            ca=ca,
        )

        # The new CA cert has been saved to the keystore earlier
        read_stored_ca.return_value = ca

        self.charm._restart_opensearch_event = MagicMock()
        self.harness.model.unit.status = MaintenanceStatus()

        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=leader)
            self.harness.update_relation_data(
                self.rel_id,
                "opensearch",
                {"security_index_initialised": "True", "admin_user_initialized": "True"},
            )

            # We passed the 1st stage of the certificate renewalV
            self.harness.update_relation_data(
                self.rel_id, "opensearch/0", {"tls_ca_renewing": "True", "tls_ca_renewed": "True"}
            )

        reload_tls_certificates.side_effect = None
        mock_response_put_transport_cert("1.1.1.1")
        mock_response_put_http_cert("1.1.1.1")
        original_status = self.harness.model.unit.status

        self.charm.tls._on_certificate_available(event_mock)

        mock_remove_ca_from_request_bundle.assert_called_once()

        # Saving new cert, cleaning up CA renewal flag, removing old CA from keystore
        # Note: the high number of operations come from the fact that on each certificate received
        # the 'issuer' is checked on each certificate that is saved on the disk.
        if self.charm.unit.is_leader():
            assert run_cmd.call_count == 14
        else:
            assert run_cmd.call_count == 16

        assert re.search(
            "openssl pkcs12 -export .* -out "
            rf"/var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12 .* -name {cert_type}",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            f"chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/{cert_type}.p12"
            in run_cmd.call_args_list[1].args[0]
        )
        assert re.search("keytool .*-delete .*-alias old-ca", run_cmd.call_args_list[-1].args[0])
        assert (
            "/var/snap/opensearch/current/etc/opensearch"
            in named_temporary_file.call_args_list[0][1]["dir"]
        )

        assert "tls_ca_renewing" not in self.harness.get_relation_data(self.rel_id, "opensearch/0")
        assert "tls_ca_renewed" not in self.harness.get_relation_data(self.rel_id, "opensearch/0")

        assert self.harness.model.unit.status.message == ""
        assert self.harness.model.unit.status, MaintenanceStatus != original_status

    # Additional potential phases of the workflow

    # Mock to investigate/compare/alter
    @parameterized.expand(
        list(
            itertools.product(
                [
                    (DeploymentType.MAIN_ORCHESTRATOR),
                    (DeploymentType.OTHER),
                    (DeploymentType.FAILOVER_ORCHESTRATOR),
                ],
                [True, False],
            )
        )
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._add_ca_to_request_bundle")
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mock to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_rotation_ongoing_on_this_unit(
        # NOTE: Syntax: parametrized parameter comes first
        self,
        deployment_type,
        leader,
        _,
        get_assigned_certificate,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
        read_stored_ca,
        deployment_desc,
        run_cmd,
        named_temporary_file,
        __,
    ):
        """Additional 'certificate-available' event while processing CA rotation.

        This run represents a 'certificate-available' right before the leader
        sets the TLS renewal flags in the peer relation.

        In this case, the leader must execute the update logic for itself.

        Remaining units will just wait until the first flags are set, hence
        will not have `run_cmd` calls.

        Applies to:
         - any deployment
         - any unit
        """
        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"
        csr = "csr_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey("key"),
        )

        read_stored_ca.return_value = "stored_ca"

        # Applies to ANY deployment type
        org = "test-org"
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        with self.harness.hooks_disabled():
            self.harness.set_leader(is_leader=True)
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_admin_certificate_requests()[0]
        )
        self.harness.set_leader(is_leader=leader)

        self.charm.on.certificate_available = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )

        # This unit is within the process of certificate renewal
        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.rel_id, f"{self.charm.unit.name}", {"tls_ca_renewing": "True"}
            )

        self.charm.tls._on_certificate_available(self.charm.on.certificate_available)

        # exactly three run_cmd commands to be executed: checking the current CA for the
        # admin cert, the unit_http cert and the unit_transport cert
        if leader:
            assert run_cmd.call_count == 3
            assert self.harness.model.unit.status == MaintenanceStatus(
                "Applying new CA certificate..."
            )
            assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
                "key": "key",
                "chain": "new_chain",
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "new_ca",
                "cert": "new_cert",
                "csr": csr,
                "subject": f"/O={org}/CN={self.harness.charm.tls._get_admin_certificate_requests()[0].common_name}",
            }
        else:
            # We have scope == Scope.APP, so we will skip the entire logic
            assert run_cmd.call_count == 0
            assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            }

    # Mock to investigate/compare/alter
    @parameterized.expand(
        list(
            itertools.product(
                [
                    (DeploymentType.MAIN_ORCHESTRATOR),
                    (DeploymentType.OTHER),
                    (DeploymentType.FAILOVER_ORCHESTRATOR),
                ],
                [True, False],
            )
        )
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateSigningRequest.from_string"
    )
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.CertificateRequestAttributes.from_csr"
    )
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._add_ca_to_request_bundle")
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    # Mock to avoid I/O
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(
        "charms.tls_certificates_interface.v4.tls_certificates.TLSCertificatesRequiresV4.get_assigned_certificate"
    )
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_rotation_ongoing_on_another_unit(
        # NOTE: Syntax: parametrized parameter comes first
        self,
        deployment_type,
        leader,
        _,
        get_assigned_certificate,
        read_stored_ca,
        deployment_desc,
        run_cmd,
        __,
        mock_add_ca_to_request_bundle,
        certificate_request_attributes_from_csr,
        certificate_signing_request_from_string,
    ):
        """Additional 'certificate-available' event while processing CA rotation.

        In this case, the leader must execute the update logic for itself.

        Remaining units will just wait until the first flags are set, hence
        will not have `run_cmd` calls.

        Applies to:
         - any deployment
         - any unit
        """
        org = "test-org"
        self.harness.set_leader(is_leader=True)
        # Applies to ANY deployment type
        deployment_desc.return_value = DeploymentDescription(
            config=PeerClusterConfig(
                cluster_name=org, init_hold=False, roles=[], profile="production"
            ),
            start=StartMode.WITH_GENERATED_ROLES,
            pending_directives=[],
            typ=deployment_type,
            app=App(model_uuid=self.charm.model.uuid, name=self.charm.app.name),
            state=DeploymentState(value=State.ACTIVE),
        )
        certificate_signing_request_from_string.return_value = Mock()
        certificate_request_attributes_from_csr.return_value = (
            self.harness.charm.tls._get_admin_certificate_requests()[0]
        )
        self.harness.set_leader(is_leader=leader)
        cert = "new_cert"
        chain = ["new_chain"]
        ca = "new_ca"
        csr = "csr_12345"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )
        get_assigned_certificate.return_value = (
            Mock(),
            PrivateKey("key"),
        )

        read_stored_ca.return_value = "stored_ca"

        self.charm.on.certificate_available = MagicMock(
            certificate_signing_request=csr, chain=chain, certificate=cert, ca=ca
        )

        # This unit has updated CA certificate
        # but another unit of the cluster is still within the process
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/1")
        with self.harness.hooks_disabled():
            self.harness.update_relation_data(
                self.rel_id, f"{self.charm.app.name}/0", {"tls_ca_renewed": "True"}
            )
            self.harness.update_relation_data(
                self.rel_id, f"{self.charm.app.name}/1", {"tls_ca_renewing": "True"}
            )

        self.charm.tls._on_certificate_available(self.charm.on.certificate_available)

        # exactly three run_cmd commands to be executed: checking the current CA for the
        # admin cert, the unit_http cert and the unit_transport cert
        if leader:
            assert run_cmd.call_count == 3
            assert self.harness.model.unit.status == MaintenanceStatus(
                "Applying new CA certificate..."
            )
            assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
                "chain": "new_chain",
                "key": "key",
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "new_ca",
                "cert": "new_cert",
                "csr": csr,
                "subject": f"/O={org}/CN={self.harness.charm.tls._get_admin_certificate_requests()[0].common_name}",
            }
        else:
            # We have scope == Scope.APP, so we will skip the entire logic
            assert run_cmd.call_count == 0
            assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            }
