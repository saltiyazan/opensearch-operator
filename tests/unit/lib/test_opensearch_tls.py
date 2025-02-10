# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""Unit test for the helper_cluster library."""
import re
import socket
import unittest
from unittest import mock
from unittest.mock import MagicMock, Mock, patch

from charms.opensearch.v0.constants_charm import PeerRelationName
from charms.opensearch.v0.constants_tls import (
    TLS_RELATION_ADMIN,
    TLS_RELATION_CLIENT,
    TLS_RELATION_PEER,
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
from ops.testing import Harness
from parameterized import parameterized

from charm import OpenSearchOperatorCharm
from tests.helpers import patch_network_get


def single_space(input: str) -> str:
    """Replace multiple spaces with one."""
    return " ".join(input.split())


@patch_network_get("1.1.1.1")
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
        self.addCleanup(self.harness.cleanup)
        self.rel_id = self.harness.add_network("1.1.1.1", endpoint=PeerRelationName)

        # Add the three TLS relations
        self.harness.add_network("1.1.1.1", endpoint=TLS_RELATION_PEER)
        self.harness.add_network("1.1.1.1", endpoint=TLS_RELATION_CLIENT)
        self.harness.add_network("1.1.1.1", endpoint=TLS_RELATION_ADMIN)

        self.harness.begin()
        self.charm = self.harness.charm

        self.rel_id = self.harness.add_relation(PeerRelationName, self.charm.app.name)
        self.harness.add_relation_unit(self.rel_id, f"{self.charm.app.name}/0")

        # Add the three TLS relations
        self.harness.add_relation(TLS_RELATION_PEER, self.charm.app.name)
        self.harness.add_relation(TLS_RELATION_CLIENT, self.charm.app.name)
        self.harness.add_relation(TLS_RELATION_ADMIN, self.charm.app.name)

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
        base_dns_entries = [self.charm.unit_name, "nebula", "alias"]

        unit_http_sans = self.charm.tls._get_sans(CertType.UNIT_HTTP)
        self.assertDictEqual(
            dict((key, sorted(val)) for key, val in unit_http_sans.items()),
            {
                "sans_oid": ["1.2.3.4.5.5"],
                "sans_ip": sorted(base_ips + ["XX.XXX.XX.XXX"]),
                "sans_dns": sorted(base_dns_entries),
            },
        )

        unit_transport_sans = self.charm.tls._get_sans(CertType.UNIT_TRANSPORT)
        self.assertDictEqual(
            dict((key, sorted(val)) for key, val in unit_transport_sans.items()),
            {
                "sans_oid": ["1.2.3.4.5.5"],
                "sans_ip": sorted(base_ips),
                "sans_dns": sorted(base_dns_entries),
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
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_on_tls_relation_created_creates_all_passwords_for_main_orchestrator_leader(
        self,
        _create_keystore_pwd_if_not_exists,
        deployment_desc,
        _put_or_update_internal_user_leader,
        _purge_users,
    ):
        """Main orchestrator leader should create passwords the keystores"""
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
        self.harness.set_leader(is_leader=True)

        self.charm.tls._on_tls_relation_created(MagicMock())

        self.assertEqual(
            _create_keystore_pwd_if_not_exists.mock_calls,
            [
                mock.call(Scope.APP, CertType.APP_ADMIN, "ca"),
                mock.call(Scope.APP, CertType.APP_ADMIN, CertType.APP_ADMIN.val),
                mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT, CertType.UNIT_TRANSPORT.val),
                mock.call(Scope.UNIT, CertType.UNIT_HTTP, CertType.UNIT_HTTP.val),
            ],
        )

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    @patch(f"{BASE_LIB_PATH}.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    def test_on_tls_relation_created_creates_only_unit_passwords_for_non_leader(
        self, _create_keystore_pwd_if_not_exists, deployment_desc
    ):
        """Non-leader units should only create their unit keystore passwords."""
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
        self.harness.set_leader(is_leader=False)
        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {"truststore-password": "test-password"},
        )

        self.charm.tls._on_tls_relation_created(MagicMock())

        self.assertEqual(
            _create_keystore_pwd_if_not_exists.mock_calls,
            [
                mock.call(Scope.UNIT, CertType.UNIT_TRANSPORT, CertType.UNIT_TRANSPORT.val),
                mock.call(Scope.UNIT, CertType.UNIT_HTTP, CertType.UNIT_HTTP.val),
            ],
        )

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    def test_on_tls_relation_created_defers_when_no_truststore_password(self, deployment_desc):
        """Non-main orchestrator units should defer if truststore password isn't available."""
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
        event = MagicMock()

        self.charm.tls._on_tls_relation_created(event)

        event.defer.assert_called_once()

    @patch(
        f"{BASE_LIB_PATH}.opensearch_peer_clusters.OpenSearchPeerClustersManager.deployment_desc"
    )
    def test_on_tls_relation_created_defers_when_no_deployment_desc(self, deployment_desc):
        """Should defer if deployment description isn't available."""
        deployment_desc.return_value = None
        event = MagicMock()

        self.charm.tls._on_tls_relation_created(event)

        event.defer.assert_called_once()

    @patch("charm.OpenSearchOperatorCharm.on_tls_relation_broken")
    def test_on_relation_broken(self, on_tls_relation_broken):
        """Test on certificate relation broken event."""
        event_mock = MagicMock()
        self.charm.tls._on_tls_relation_broken(event_mock)

        on_tls_relation_broken.assert_called_once()

    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS._create_keystore_pwd_if_not_exists")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    @patch("charm.OpenSearchOperatorCharm._purge_users")
    def test_regenerate_tls_private_key(self, _, __, deployment_desc):
        """Test regenerate_tls_private_key action handler.

        The charm leader unit should regenerate private key for app-admin certs.
        Any unit can regenerate its own unit certs.
        """
        event_mock = MagicMock(params={"category": "app-admin"})

        self.harness.set_leader(is_leader=False)
        deployment_desc.return_value = self.deployment_descriptions["ok"]
        self.charm.tls._on_set_tls_private_key(event_mock)
        self.certs_admin.regenerate_private_key.assert_not_called()

        self.harness.set_leader(is_leader=True)
        self.charm.tls._on_set_tls_private_key(event_mock)
        self.certs_admin.regenerate_private_key.assert_called_once()

        event_mock = MagicMock(params={"category": "unit-transport"})
        self.harness.set_leader(is_leader=False)
        self.charm.tls._on_set_tls_private_key(event_mock)
        self.certs_peer.regenerate_private_key.assert_called_once()

        event_mock = MagicMock(params={"category": "unit-http"})
        self.charm.tls._on_set_tls_private_key(event_mock)
        self.certs_client.regenerate_private_key.assert_called_once()

    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def test_on_certificate_available_transport(self, _, store_new_ca, on_tls_conf_set):
        """Test certificate available event for transport certificate."""
        csr = "csr_12345"
        cert = "cert_12345"
        chain = ["chain_12345"]
        ca = "ca_12345"
        keystore_password = "keystore_12345"

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT.val,
            {"csr": csr, "keystore-password": keystore_password},
        )

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {"truststore-password": "truststore_12345"},
        )

        event_mock = MagicMock(
            certificate_signing_request=csr,
            chain=chain,
            certificate=cert,
            ca=ca,
        )

        self.charm.certs_peer._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val),
            {
                "csr": csr,
                "chain": chain[0],
                "cert": cert,
                "ca-cert": ca,
                "keystore-password": keystore_password,
            },
        )

        on_tls_conf_set.assert_called_once()

    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def test_on_certificate_available_http(self, _, store_new_ca, on_tls_conf_set):
        """Test certificate available event for HTTP certificate."""
        csr = "csr_http"
        cert = "cert_http"
        chain = ["chain_http"]
        ca = "ca_http"
        keystore_password = "keystore_http"

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP.val,
            {"csr": csr, "keystore-password": keystore_password},
        )

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {"truststore-password": "truststore_12345"},
        )

        event_mock = MagicMock(
            certificate_signing_request=csr,
            chain=chain,
            certificate=cert,
            ca=ca,
        )

        self.charm.certs_client._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.UNIT, CertType.UNIT_HTTP.val),
            {
                "csr": csr,
                "chain": chain[0],
                "cert": cert,
                "ca-cert": ca,
                "keystore-password": keystore_password,
            },
        )

        on_tls_conf_set.assert_called_once()

    @patch("charm.OpenSearchOperatorCharm.on_tls_conf_set")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.store_new_ca")
    @patch("charm.OpenSearchOperatorCharm._put_or_update_internal_user_leader")
    def test_on_certificate_available_admin(self, _, store_new_ca, on_tls_conf_set):
        """Test certificate available event for admin certificate."""
        csr = "csr_admin"
        cert = "cert_admin"
        chain = ["chain_admin"]
        ca = "ca_admin"
        keystore_password = "keystore_admin"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": csr,
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=csr,
            chain=chain,
            certificate=cert,
            ca=ca,
        )

        self.charm.certs_admin._on_certificate_available(event_mock)

        self.assertDictEqual(
            self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val),
            {
                "csr": csr,
                "chain": chain[0],
                "cert": cert,
                "ca-cert": ca,
                "keystore-password": keystore_password,
                "truststore-password": "truststore_12345",
            },
        )

        on_tls_conf_set.assert_called_once()

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
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_leader_certificate_workflow(
        self,
        deployment_type,
        _,
        deployment_desc,
        read_stored_ca,
        run_cmd,
        named_temporary_file,
    ):
        """Test full certificate workflow for leader unit.

        Leader unit should:
        - Handle admin cert through admin interface
        - Handle transport cert through peer interface
        - Handle HTTP cert through client interface
        - Save all certs to Juju secrets
        - Save all certs to keystores
        """
        # Setup initial state
        self.harness.set_leader(is_leader=True)
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

        admin_csr = "admin_csr"
        admin_cert = "admin_cert"
        admin_chain = ["admin_chain"]
        admin_ca = "admin_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": admin_csr,
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
            },
        )

        admin_event = MagicMock(
            certificate_signing_request=admin_csr,
            chain=admin_chain,
            certificate=admin_cert,
            ca=admin_ca,
        )
        self.charm.certs_admin._on_certificate_available(admin_event)

        assert re.search(
            f"openssl pkcs12 -export .* -out .*/certificates/{CertType.APP_ADMIN}.p12 .* -name {CertType.APP_ADMIN}",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            f"chmod +r .*/certificates/{CertType.APP_ADMIN}.p12"
            in run_cmd.call_args_list[1].args[0]
        )

        transport_csr = "transport_csr"
        transport_cert = "transport_cert"
        transport_chain = ["transport_chain"]
        transport_ca = "transport_ca"

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT.val,
            {
                "csr": transport_csr,
                "keystore-password": "keystore_12345",
            },
        )

        transport_event = MagicMock(
            certificate_signing_request=transport_csr,
            chain=transport_chain,
            certificate=transport_cert,
            ca=transport_ca,
        )
        self.charm.certs_peer._on_certificate_available(transport_event)

        assert re.search(
            f"openssl pkcs12 -export .* -out .*/certificates/{CertType.UNIT_TRANSPORT}.p12 .* -name {CertType.UNIT_TRANSPORT}",
            run_cmd.call_args_list[2].args[0],
        )
        assert (
            f"chmod +r .*/certificates/{CertType.UNIT_TRANSPORT}.p12"
            in run_cmd.call_args_list[3].args[0]
        )

        http_csr = "http_csr"
        http_cert = "http_cert"
        http_chain = ["http_chain"]
        http_ca = "http_ca"

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP.val,
            {
                "csr": http_csr,
                "keystore-password": "keystore_12345",
            },
        )

        http_event = MagicMock(
            certificate_signing_request=http_csr,
            chain=http_chain,
            certificate=http_cert,
            ca=http_ca,
        )
        self.charm.certs_client._on_certificate_available(http_event)

        assert re.search(
            f"openssl pkcs12 -export .* -out .*/certificates/{CertType.UNIT_HTTP}.p12 .* -name {CertType.UNIT_HTTP}",
            run_cmd.call_args_list[4].args[0],
        )
        assert (
            f"chmod +r .*/certificates/{CertType.UNIT_HTTP}.p12"
            in run_cmd.call_args_list[5].args[0]
        )

        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": admin_csr,
            "cert": admin_cert,
            "chain": admin_chain[0],
            "ca-cert": admin_ca,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
        }

        assert self.secret_store.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val) == {
            "csr": transport_csr,
            "cert": transport_cert,
            "chain": transport_chain[0],
            "ca-cert": transport_ca,
            "keystore-password": "keystore_12345",
        }

        assert self.secret_store.get_object(Scope.UNIT, CertType.UNIT_HTTP.val) == {
            "csr": http_csr,
            "cert": http_cert,
            "chain": http_chain[0],
            "ca-cert": http_ca,
            "keystore-password": "keystore_12345",
        }

        # Verify total keystore operations
        assert run_cmd.call_count == 6  # 3 certs * (create keystore + chmod)

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
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_on_certificate_available_ca_rotation(
        self,
        deployment_type,
        _,
        deployment_desc,
        read_stored_ca,
        run_cmd,
        named_temporary_file,
    ):
        """Test CA rotation through admin certificate interface.

        When receiving a new CA through the admin cert interface:
        - New CA cert should be saved to truststore
        - New admin cert should be saved to secrets
        - Service should be restarted to load new CA
        """
        old_csr = "old_csr"
        new_cert = "new_cert"
        new_chain = ["new_chain"]
        new_ca = "new_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": old_csr,
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
                "ca-cert": "old_ca_cert",
                "cert": "old_cert",
            },
        )

        event_mock = MagicMock(
            certificate_signing_request=old_csr,
            chain=new_chain,
            certificate=new_cert,
            ca=new_ca,
        )

        read_stored_ca.return_value = "old_ca"

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

        self.charm._restart_opensearch_event = MagicMock()
        self.harness.set_leader(is_leader=True)

        self.charm.certs_admin._on_certificate_available(event_mock)

        assert run_cmd.call_count == 2
        assert re.search(
            "keytool *-importcert.* *-alias ca",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            "chmod +r /var/snap/opensearch/current/etc/opensearch/certificates/ca.p12"
            in run_cmd.call_args_list[1].args[0]
        )

        self.charm._restart_opensearch_event.emit.assert_called_once()

        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": old_csr,
            "cert": new_cert,
            "chain": new_chain[0],
            "truststore-password": "truststore_12345",
            "keystore-password": "keystore_12345",
            "ca-cert": new_ca,
        }

    @parameterized.expand(
        [
            (DeploymentType.MAIN_ORCHESTRATOR),
            (DeploymentType.OTHER),
            (DeploymentType.FAILOVER_ORCHESTRATOR),
        ]
    )
    @patch("charms.opensearch.v0.opensearch_tls.tempfile.NamedTemporaryFile")
    @patch("charms.opensearch.v0.opensearch_tls.run_cmd")
    @patch("charms.opensearch.v0.opensearch_tls.OpenSearchTLS.read_stored_ca")
    @patch(f"{PEER_CLUSTERS_MANAGER}.deployment_desc")
    @patch("builtins.open", side_effect=unittest.mock.mock_open())
    def test_non_leader_certificate_workflow(
        self,
        deployment_type,
        _,
        deployment_desc,
        read_stored_ca,
        run_cmd,
        named_temporary_file,
    ):
        """Test full certificate workflow for non-leader unit.

        Non-leader unit should:
        - Not handle admin cert events
        - Handle transport cert through peer interface
        - Handle HTTP cert through client interface
        - Save all certs to keystores
        """
        self.harness.set_leader(is_leader=False)
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

        admin_csr = "admin_csr"
        admin_cert = "admin_cert"
        admin_chain = ["admin_chain"]
        admin_ca = "admin_ca"

        self.secret_store.put_object(
            Scope.APP,
            CertType.APP_ADMIN.val,
            {
                "csr": admin_csr,
                "cert": admin_cert,
                "chain": admin_chain[0],
                "ca-cert": admin_ca,
                "keystore-password": "keystore_12345",
                "truststore-password": "truststore_12345",
            },
        )

        transport_csr = "transport_csr"
        transport_cert = "transport_cert"
        transport_chain = ["transport_chain"]
        transport_ca = "transport_ca"

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_TRANSPORT.val,
            {
                "csr": transport_csr,
                "keystore-password": "keystore_12345",
            },
        )

        transport_event = MagicMock(
            certificate_signing_request=transport_csr,
            chain=transport_chain,
            certificate=transport_cert,
            ca=transport_ca,
        )
        self.charm.certs_peer._on_certificate_available(transport_event)

        assert re.search(
            f"openssl pkcs12 -export .* -out .*/certificates/{CertType.UNIT_TRANSPORT}.p12 .* -name {CertType.UNIT_TRANSPORT}",
            run_cmd.call_args_list[0].args[0],
        )
        assert (
            f"chmod +r .*/certificates/{CertType.UNIT_TRANSPORT}.p12"
            in run_cmd.call_args_list[1].args[0]
        )

        http_csr = "http_csr"
        http_cert = "http_cert"
        http_chain = ["http_chain"]
        http_ca = "http_ca"

        self.secret_store.put_object(
            Scope.UNIT,
            CertType.UNIT_HTTP.val,
            {
                "csr": http_csr,
                "keystore-password": "keystore_12345",
            },
        )

        http_event = MagicMock(
            certificate_signing_request=http_csr,
            chain=http_chain,
            certificate=http_cert,
            ca=http_ca,
        )
        self.charm.certs_client._on_certificate_available(http_event)

        assert re.search(
            f"openssl pkcs12 -export .* -out .*/certificates/{CertType.UNIT_HTTP}.p12 .* -name {CertType.UNIT_HTTP}",
            run_cmd.call_args_list[2].args[0],
        )
        assert (
            f"chmod +r .*/certificates/{CertType.UNIT_HTTP}.p12"
            in run_cmd.call_args_list[3].args[0]
        )

        assert self.secret_store.get_object(Scope.UNIT, CertType.UNIT_TRANSPORT.val) == {
            "csr": transport_csr,
            "cert": transport_cert,
            "chain": transport_chain[0],
            "ca-cert": transport_ca,
            "keystore-password": "keystore_12345",
        }

        assert self.secret_store.get_object(Scope.UNIT, CertType.UNIT_HTTP.val) == {
            "csr": http_csr,
            "cert": http_cert,
            "chain": http_chain[0],
            "ca-cert": http_ca,
            "keystore-password": "keystore_12345",
        }

        assert self.secret_store.get_object(Scope.APP, CertType.APP_ADMIN.val) == {
            "csr": admin_csr,
            "cert": admin_cert,
            "chain": admin_chain[0],
            "ca-cert": admin_ca,
            "keystore-password": "keystore_12345",
            "truststore-password": "truststore_12345",
        }

        assert run_cmd.call_count == 4  # 2 certs * (create keystore + chmod)
