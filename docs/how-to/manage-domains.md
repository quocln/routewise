# Manage domain lists

Each VPN has its own list, and there is one more called **Any VPN**. A destination in a VPN's list
goes only through that VPN. See [how routing decisions are made](../explanation/routing.md).

## In the app

1. Open the **Domains** tab.
2. Pick a list in the sidebar.
3. Type or paste entries into the add field. Separate several with commas, spaces or new lines.

Changes apply at once. For what an entry may be, see [List entries](../reference/list-entries.md).

## From the command line

These edit the **Any VPN** list:

```bash
routewise add-domain "*.corp.example.com"
routewise add-domain 10.20.0.0/16
routewise remove-domain "*.corp.example.com"
routewise list-domains
```

Per-VPN lists are edited in the app.

## Check an entry works

```bash
routewise check jira.corp.example.com
```

This asks the kernel where traffic to each address goes, so the answer is what traffic will do.
If an entry was refused, the **Events** view in the **Activity** tab says why.

Wildcards are routed as names are looked up, so a wildcard route appears only after the first
lookup. Apps with their own DNS-over-HTTPS skip this; see
[Wildcard domains are not routed](troubleshoot.md#wildcard-domains-are-not-routed).
