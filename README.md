# Identity Manager

An identity & account management system, incorporating multiple authentication strategies, address verification and RBAC.

## Purpose

This service provides centralized identity management. An identity can be associated with an email address, one or more authentication credentials and verifiable addresses. Also, a simple implementation of RBAC with identity-assigned groups is supported. This service is meant to be an entrypoint for all authn/authz operations in your architecture.

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
