# Copyright 2024 Canonical Ltd.
# See LICENSE file for licensing details.

"""In this file we declare the constants and enums used by TLS related components."""
from charms.opensearch.v0.helper_enums import BaseStrEnum

# The unique Charmhub library identifier, never change it
LIBID = "2f539a53ab0a4916957beaf1d6b27124"

# Increment this major API version when introducing breaking changes
LIBAPI = 0

# Increment this PATCH version before using `charmcraft publish-lib` or reset
# to 0 if you are raising the major API version
LIBPATCH = 1


# Base name for TLS relations
TLS_RELATION = "certificates"

# Full relation names
TLS_RELATION_ADMIN = f"{TLS_RELATION}-admin"
TLS_RELATION_TRANSPORT = f"{TLS_RELATION}-transport"
TLS_RELATION_HTTP = f"{TLS_RELATION}-http"


class CertType(BaseStrEnum):
    """Certificate types."""

    APP_ADMIN = "app-admin"  # admin / management of cluster
    # APP_CLIENT_HTTP = "app-client-http"  # external http clients (rest layer)
    UNIT_TRANSPORT = "unit-transport"  # internal node to node communication (transport layer)
    UNIT_HTTP = "unit-http"  # http for nodes (rest layer) - units act as servers


class TlsFileExt(BaseStrEnum):
    """Extensions of TLS generated files."""

    CA = ".ca"
    CERT = ".cert"
    CHAIN = ".chain"
    CSR = ".csr"
    KEY = ".key"
    KEYPASS = ".key-password"
