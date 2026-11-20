# Threat Hunting en KQL contra ataques automatizados con IA (ARTEX)

Repositorio defensivo con plantillas reutilizables (`.kql`), consultas de *Threat Hunting* (`.kql`) y una regla analítica programada (`.yaml`) orientadas a detectar patrones de comportamiento y artefactos asociados a frameworks agénticos de pentesting automatizado (como **ARTEX**) en **Microsoft Sentinel** y **Microsoft Defender XDR**.

> **Uso exclusivamente defensivo y de laboratorio:** Estas consultas están diseñadas para proteger infraestructura propia o autorizada. No se han ejecutado en un entorno de producción real; antes de activarlas como alertas críticas, valida los esquemas (`| getschema`), calibra los umbrales con tráfico base (`T2`) y configura exclusiones (`T3`).

---

## Estructura del repositorio

```text
artex-kql-hunting-playbook/
├── README.md
├── docs
├── templates/
│   ├── T1_burst_template.kql
│   ├── T2_baseline_calibration.kql
│   └── T3_allowlist_pattern.kql
├── queries/
│   ├── identity-cloud/
│   │   ├── Q01_retrohunt_ioc_ips.kql
│   │   ├── Q02_spn_invalid_secret_then_success.kql
│   │   ├── Q03_ip_multiple_spns_mixed_results.kql
│   │   ├── Q04_spn_multi_plane_token_sweep.kql
│   │   ├── Q05_keyvault_secret_burst.kql
│   │   ├── Q06_vm_runcommand_by_spn.kql
│   │   ├── Q07_app_credential_consent_persistence.kql
│   │   └── Q08_storage_blob_mass_download.kql
│   ├── web-network/
│   │   ├── Q09_artex_user_agent.kql
│   │   ├── Q10_x_artx_key_header.kql
│   │   ├── Q11_web_scan_burst_4xx.kql
│   │   ├── Q12_random_404_canary_then_sweep.kql
│   │   ├── Q13_machine_cadence_short_intervals.kql
│   │   └── Q14_lfi_php2shell_indicators.kql
│   └── endpoint-decoys/
│       ├── Q15_webserver_spawning_shells.kql
│       └── Q16_decoy_honeytoken_identities.kql
└── analytics-rules/
    └── sentinel_spn_mixed_auth_rule.yaml
```

---

## Resumen de consultas y cobertura MITRE ATT&CK

| ID | Archivo | Capa | Técnicas MITRE ATT&CK |
|---|---|---|---|
| **T1** | `templates/T1_burst_template.kql` | Plantilla | Normalización tabular (`Client`, `Resource`, `Failed`) |
| **T2** | `templates/T2_baseline_calibration.kql` | Plantilla | Cálculo de percentiles (`p50`, `p95`, `p99`) |
| **T3** | `templates/T3_allowlist_pattern.kql` | Plantilla | Exclusión mediante `Watchlists` y rangos CIDR |
| **Q01** | `Q01_retrohunt_ioc_ips.kql` | Identidad y Cloud | `T1078.004`, `T1528` |
| **Q02** | `Q02_spn_invalid_secret_then_success.kql` | Identidad y Cloud | `T1552.001`, `T1078.004` |
| **Q03** | `Q03_ip_multiple_spns_mixed_results.kql` | Identidad y Cloud | `T1078.004`, `T1110` |
| **Q04** | `Q04_spn_multi_plane_token_sweep.kql` | Identidad y Cloud | `T1580`, `T1087.004`, `T1530` |
| **Q05** | `Q05_keyvault_secret_burst.kql` | Identidad y Cloud | `T1555.006`, `T1552` |
| **Q06** | `Q06_vm_runcommand_by_spn.kql` | Identidad y Cloud | `T1651` |
| **Q07** | `Q07_app_credential_consent_persistence.kql` | Identidad y Cloud | `T1098.001`, `T1528` |
| **Q08** | `Q08_storage_blob_mass_download.kql` | Identidad y Cloud | `T1530` |
| **Q09** | `Q09_artex_user_agent.kql` | Web / WAF / Proxy | `T1595`, `T1588.002` |
| **Q10** | `Q10_x_artx_key_header.kql` | Web / WAF / Proxy | `T1505.003` |
| **Q11** | `Q11_web_scan_burst_4xx.kql` | Web / WAF / Proxy | `T1595.002`, `T1190` |
| **Q12** | `Q12_random_404_canary_then_sweep.kql` | Web / WAF / Proxy | `T1595.002` |
| **Q13** | `Q13_machine_cadence_short_intervals.kql` | Web / WAF / Proxy | `T1595`, `T1190` |
| **Q14** | `Q14_lfi_php2shell_indicators.kql` | Web / WAF / Proxy | `T1190` |
| **Q15** | `Q15_webserver_spawning_shells.kql` | Endpoint / Servidor | `T1505.003`, `T1059.004` |
| **Q16** | `Q16_decoy_honeytoken_identities.kql` | Engaño / Honeytokens | `T1078.004`, `T1552` |

---

## Checklist previo a producción

1. **Verificar esquema:** Ejecuta `<Tabla> | getschema` en tu workspace de Log Analytics para confirmar nombres y tipos de columna (especialmente en `AzureDiagnostics`).
2. **Calibrar umbrales:** Usa `T2_baseline_calibration.kql` sobre 14–30 días de logs históricos para fijar umbrales por encima del `p99`.
3. **Configurar Watchlists:** Crea las watchlists `KnownScanners` (`T3`) y `DecoyIdentities` (`Q16`) usando `SearchKey` como clave.
4. **Controlar el coste:** En consultas con `join` (`Q02`, `Q12`) o `search` (`Q10`), acota el `lookback` y filtra previamente para evitar consumo elevado de recursos.
5. **Gestionar TTL de IoCs:** Los indicadores de red caducan rápido; almacénalos con fecha de alta y retíralos periódicamente.
6. **Notas de depuración**: Las consultas y plantillas en .kql y la regla en .yaml parten del informe original en PDF, pero se han limpiado y reformateado para corregir errores de extracción/sintaxis del documento (como operadores |, asignaciones o expresiones regulares cortadas) y estructurarlas por capas. No se han ejecutado en un entorno de producción real.