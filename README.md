# Identity Manager

An identity & account management system, incorporating multiple authentication strategies, address verification and RBAC.

## Purpose

This service allows to employ the company internal account management system as an identity provider for the OAuth 2.0 stack. It can be used in tandem with [ORY Hydra](https://github.com/ory/hydra) and [api-gateway](https://github.com/mpraski/api-gateway) to provide a flexible, tested cluster-wide authentication & authorization scheme.

## Builing

To build for you local architecture:

```bash
make build
```

To build for Linux x86-68:

```bash
make compile
```

To run with example config:

```bash
make run
```

## Authors

- [Marcin Praski](https://github.com/mpraski)
