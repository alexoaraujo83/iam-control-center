# Reconciliação da baseline PostgreSQL com Neon

**Status:** BLOCKED — restore CI detectou dump versionado desatualizado: current_tenant_id() ainda inclui public no search_path, divergindo da fonte Neon hardened. Export autenticado e comparação objeto-a-objeto pendentes.  
**Repositório:** `alexoaraujo83/iam-control-center`  
**Branch desta documentação:** `chore/reconcile-neon-source-schema-baseline`  
**Base GitHub:** `main` em `ff71607948c9d02d90fc0b1b26931c573ab660f8`  
**Arquivo de bootstrap em main:** `database/bootstrap/0001_initial_iam_schema.sql`  
**Blob SHA observado:** `18ff99eade3a216df2396b564fe11de6482dc8d8`

## Decisão de fonte oficial

A decisão aprovada é usar o schema operacional de `iam-database-delivery / iam_database` como referência oficial para reconciliar a baseline do repositório IAM Control Center.

Identificação da fonte consultada (somente leitura):

- Neon project ID: `twilight-fire-88497009`
- Branch ID: `br-little-fire-b6adup9f` (branch principal do projeto consultado)
- Database: `iam_database`
- PostgreSQL: `18.6 (ac70818)`
- Região: `aws-sa-east-1`

Esta decisão define a fonte de verdade estrutural para a reconciliação. Não autoriza alterações na fonte, execução de migrations, cópia de dados, rotação de credenciais, nem alterações em Production.

## Inventário estrutural confirmado

Consulta ao catálogo PostgreSQL nos schemas `iam`, `audit` e `app_private`:

| Objeto | Quantidade |
|---|---:|
| Tabelas | 23 |
| Views | 1 |
| Policies RLS | 41 |
| Tabelas com RLS habilitado | 20 |
| Tabelas com FORCE ROW LEVEL SECURITY | 20 |
| Funções/procedures | 9 |
| Tipos ENUM | 7 |
| Triggers não internos | 12 |

### Tabelas

- `app_private.context_keys`
- `audit.events`
- `audit.outbox`
- `iam.access_policies`
- `iam.api_keys`
- `iam.group_memberships`
- `iam.group_roles`
- `iam.groups`
- `iam.idempotency_keys`
- `iam.identities`
- `iam.identity_providers`
- `iam.invitations`
- `iam.membership_roles`
- `iam.memberships`
- `iam.organizations`
- `iam.permissions`
- `iam.role_permissions`
- `iam.roles`
- `iam.schema_migrations`
- `iam.security_events`
- `iam.service_accounts`
- `iam.sessions`
- `iam.tenants`

View: `iam.v_effective_membership_permissions`.

As 41 policies foram inventariadas com comando, roles, expressão `USING` e `WITH CHECK`. A matriz de privilégios foi consultada com funções `has_schema_privilege`, `has_table_privilege` e `has_function_privilege` para as roles operacionais e de migração.

## Divergência da bootstrap inicial versionado

O arquivo `database/bootstrap/0001_initial_iam_schema.sql` em `main` declara no cabeçalho:

- `REVIEW PROPOSAL`;
- banco limpo;
- sem extensões, seeds, policies ou grants de runtime;
- RLS sem policies como default-deny.

A proposta cria somente um subconjunto do modelo observado no Neon. Exemplos de objetos existentes na fonte e ausentes na proposta incluem:

- `app_private.context_keys`;
- `audit.outbox`;
- `iam.access_policies`;
- `iam.api_keys`;
- `iam.groups` e suas tabelas de associação;
- `iam.identity_providers`;
- `iam.idempotency_keys`;
- `iam.organizations`;
- `iam.security_events`;
- `iam.service_accounts`;
- `iam.sessions`;
- `iam.v_effective_membership_permissions`.

Portanto, a migration atual não pode ser tratada como reprodução fiel do schema operacional nem como baseline integral para testes RLS.

## Evidência relacionada ao hardening

A fonte consultada apresenta o índice parcial único `app_private.context_keys_one_active_idx`, válido e com predicado `(active IS TRUE)`, e a função `app_private.current_tenant_id()` com `SECURITY DEFINER` e `search_path` endurecido para `pg_catalog, app_private, iam`.

O ledger da fonte contém a migration `0001_context_key_hardening`, checksum SHA-256 `2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab`, source SHA `b80c98c51746e1d49039015eb649b9bdd735ef7f` e execution role `iam_migrator_login`.

Observação: a fonte e uma branch isolada anteriormente consultada apresentaram ledger idêntico. A origem temporal dessa igualdade não foi estabelecida. Este documento não atribui causa nem presume execução independente.

## Extração detalhada — rodada 1 (catálogo read-only)

Em 2026-11-05 foi executada uma extração adicional de metadados diretamente do catálogo PostgreSQL da mesma fonte. A consulta composta retornou parte do snapshot estrutural, mas a resposta foi truncada pelo limite de saída; portanto, esta rodada **não é classificada como export DDL integral**.

Evidências detalhadas obtidas em consultas menores:

- PostgreSQL 18.6; schemas `iam`, `audit` e `app_private` pertencem a `iam_owner`.
- 7 ENUMs: `api_key_status`, `audit_outcome`, `identity_status`, `invitation_status`, `membership_status`, `session_status` e `tenant_status`.
- View `iam.v_effective_membership_permissions`: owner `iam_owner`, opção `security_invoker=true`; delega a resolução para `iam.effective_permissions(id)`.
- Contagens confirmadas novamente: 23 relações tabulares, 20 com RLS, 20 com FORCE RLS, 41 policies e 12 triggers não internos.
- As ACLs de tabelas foram extraídas sem consultar linhas de dados. Foram observados privilégios distintos para `iam_app_runtime`, `iam_worker` e `iam_migrator`; a extração integral e a matriz efetiva por operação ainda precisam ser normalizadas.
- As 9 funções foram identificadas e suas definições obtidas em consulta separada. Entre elas há 6 funções `SECURITY DEFINER` nos schemas examinados.

### Achado de hardening: `iam.set_tenant_context(...)`

A função `iam.set_tenant_context(uuid, uuid, bigint, text, text)` é `SECURITY DEFINER`, pertence a `iam_owner` e atualmente declara:

```sql
SET search_path TO 'pg_catalog', 'app_private', 'iam', 'public'
```

Isso diverge do padrão de hardening já observado em `app_private.current_tenant_id()` e dos demais caminhos SECURITY DEFINER que restringem o `search_path`. A consulta de ACL também confirmou que `PUBLIC` tem apenas `USAGE` no schema `public` (sem `CREATE`), e que as roles `iam_owner`, `iam_migrator`, `iam_migrator_login`, `iam_app_runtime` e `iam_worker` consultadas não têm `CREATE` em `public`. Portanto, o achado é uma **divergência de hardening a corrigir/justificar**, não evidência isolada de exploração ou de escalada efetiva.

Ação de baseline: avaliar a definição pretendida e remover `public` do `search_path` dessa função em uma migration de reconciliação separada, depois de validar dependências e comportamento em PostgreSQL descartável. Nenhuma alteração foi aplicada na fonte.

## Extração estrutural por objeto — rodada 2 (2026-11-05)

A listagem e as consultas de catálogo foram divididas por objeto para evitar o truncamento da consulta composta anterior. O inventário confirmado nesta rodada é:

| Elemento | Quantidade |
|---|---:|
| Tabelas base | 23 |
| Views | 1 |
| Colunas nas tabelas/views | 182 |
| Constraints nas tabelas | 244 |
| Índices | 63 |
| Sequências | 3 |
| ENUMs | 7 |
| Triggers não internos | 12 |
| Policies RLS | 41 |

As 3 sequências pertencem a `audit.events`, `audit.outbox` e `iam.security_events`; todas têm owner `iam_owner`.

### Flags RLS confirmadas por relação

- 20 tabelas têm RLS habilitado e FORCE RLS.
- 3 tabelas não têm RLS: `app_private.context_keys`, `iam.permissions` e `iam.schema_migrations`.
- A view `iam.v_effective_membership_permissions` usa `security_invoker=true`.
- A presença de RLS/FORCE não prova isolamento correto por si só; as expressões das policies, grants, funções chamadas e testes com roles reais ainda precisam ser validados em fixture integral.

### Triggers identificados

- `audit.events`: `audit_events_no_truncate` e `audit_events_no_update`, ambos chamam `audit.reject_event_mutation()`.
- `iam.access_policies`, `iam.groups`, `iam.identities`, `iam.identity_providers`, `iam.memberships`, `iam.organizations`, `iam.roles`, `iam.service_accounts`, `iam.sessions` e `iam.tenants`: triggers `*_touch` que chamam `iam.touch_updated_at()`.

### Restrições sensíveis confirmadas por definição

- `iam.identity_providers` rejeita chaves de segredo em texto puro no JSON `configuration`.
- `iam.api_keys.key_hash` e `iam.invitations.token_hash` têm tamanho fixo de 32 bytes.
- `iam.idempotency_keys.request_hash` tem tamanho fixo de 32 bytes.
- `iam.sessions.token_fingerprint`, quando presente, tem tamanho fixo de 32 bytes.
- `app_private.context_keys.secret` exige ao menos 32 bytes. Somente a definição da coluna/constraint foi consultada; nenhum valor foi lido.

Esta rodada fornece inventário detalhado de colunas, defaults, constraints, índices e demais metadados. Ainda não é um artefato DDL canônico reproduzível: faltam consolidar todas as definições SQL em arquivo versionado, verificar owners/ACLs de todos os tipos/rotinas/objetos e validar a ordem de dependências em PostgreSQL descartável.

## Comparação nominal com `0001_initial_iam_schema.sql` — rodada 3

A migration em `main` foi inspecionada por leitura do blob SHA `18ff99eade3a216df2396b564fe11de6482dc8d8` (258 linhas). O parser estrutural do arquivo identificou:

- 3 schemas criados: `iam`, `audit`, `app_private`.
- 10 tabelas declaradas.
- 0 tipos ENUM, 0 funções, 0 triggers, 0 views e 0 policies declaradas.

As 10 tabelas da proposta têm nomes que também existem na fonte, mas isso não implica equivalência de estrutura: a definição de colunas, constraints, índices, tipos e defaults diverge em objetos como `iam.tenants`, `iam.identities`, `iam.memberships`, `iam.roles`, `iam.permissions`, `iam.invitations`, `audit.events` e `iam.schema_migrations`.

### Objetos da fonte ausentes na migration 0001

1. `app_private.context_keys`
2. `audit.outbox`
3. `iam.access_policies`
4. `iam.api_keys`
5. `iam.group_memberships`
6. `iam.group_roles`
7. `iam.groups`
8. `iam.idempotency_keys`
9. `iam.identity_providers`
10. `iam.organizations`
11. `iam.security_events`
12. `iam.service_accounts`
13. `iam.sessions`

Além das tabelas ausentes, faltam na proposta os 7 ENUMs, a view `iam.v_effective_membership_permissions`, as 9 funções/procedures, os 12 triggers, as 41 policies e os grants operacionais observados na fonte. Assim, a migration atual é uma proposta inicial reduzida, não um baseline operacional.

**Classificação da divergência:** estrutural e semântica, não apenas diferença de nomenclatura. Não é seguro “completar” a migration 0001 em lugar, pois ela pode ter sido aplicada em ambientes ou registrada em ledgers. A estratégia precisa preservar histórico e separar bootstrap de banco novo da reconciliação de instalações existentes.

### Revisão de segurança direcionada — `iam.set_tenant_context`

Consulta read-only adicional da definição completa confirmou:

- A função apenas define GUCs transacionais `iam.tenant_id`, `iam.identity_id`, `iam.expires_at`, `iam.nonce` e `iam.signature`, chama `app_private.current_tenant_id()` com schema qualificado e limpa o contexto antes de lançar `42501` quando a validação falha.
- Não foi observado SQL dinâmico nem referência a objetos de aplicação não qualificados no corpo; `set_config` é função de catálogo `pg_catalog`.
- ACL concede EXECUTE a `iam_app_runtime` e `iam_worker`, além de `iam_owner`.
- As policies tenant-scoped inspecionadas referenciam `app_private.current_tenant_id()`; não dependem diretamente de resolução de nomes via `public`.
- A função auxiliar `app_private.current_tenant_id()` mantém `search_path=pg_catalog, app_private, iam`.

**Refinamento da classificação:** o `public` no search_path de `iam.set_tenant_context` é desnecessário para o corpo atualmente observado e viola o padrão mínimo de hardening, mas não foi identificada, nesta revisão estática, uma referência não qualificada explorável. Manter como hardening pendente; a correção proposta é restringir o search_path após validar a assinatura/definição e testar comportamento e grants em branch descartável. Nenhuma alteração na fonte.

## Matriz de privilégios efetivos — rodada 4 (2026-11-05)

Consulta read-only via `has_schema_privilege`, `has_table_privilege` e `has_function_privilege`, sem consultar dados de aplicação.

### Roles

| Role | LOGIN | SUPERUSER | BYPASSRLS | INHERIT | CREATEDB/CREATEROLE |
|---|---:|---:|---:|---:|---:|
| `iam_app_runtime` | não | não | não | sim | não/não |
| `iam_worker` | não | não | não | sim | não/não |
| `iam_migrator` | não | não | não | não | não/não |
| `iam_migrator_login` | sim | não | não | não | não/não |
| `iam_owner` | não | não | não | não | não/não |

### Privilégios por schema

- `iam_app_runtime` e `iam_worker`: USAGE em `iam`, `audit` e `app_private`; sem CREATE.
- `iam_migrator`: USAGE apenas em `iam`; sem CREATE.
- As três schemas pertencem a `iam_owner`.

### Matriz de tabelas — resumo efetivo

- `iam_app_runtime`: SELECT nas tabelas IAM tenant-scoped; INSERT/UPDATE/DELETE somente nos objetos operacionais explicitamente concedidos (incluindo `access_policies`, `idempotency_keys`, `identity_providers`, `invitations`, `organizations`, `security_events`, `service_accounts`, `sessions`, `tenants`); INSERT/SELECT em `audit.events`; INSERT em `audit.outbox`; SELECT em `iam.permissions`.
- `iam_worker`: SELECT/INSERT/UPDATE em `audit.outbox`; SELECT em `iam.permissions`; nenhum acesso às tabelas de tenant fora desses objetos.
- `iam_migrator`: SELECT em `iam.schema_migrations`; sem DML direto nas tabelas de aplicação.
- Nenhuma dessas três roles tem acesso direto a `app_private.context_keys`.
- As 20 tabelas tenant-scoped mantêm RLS + FORCE RLS; privilégios SQL não substituem o filtro das policies.

### ACLs de funções — pontos de atenção

- `iam.acquire_migration_lock()` e `iam.record_migration(...)`: EXECUTE concedido a `iam_migrator`, não a runtime/worker/PUBLIC.
- `app_private.current_tenant_id()` e `iam.set_tenant_context(...)`: EXECUTE para runtime/worker; sem EXECUTE para PUBLIC.
- `iam.provision_membership(...)`: ACL observada apenas para `iam_owner`; runtime/worker não têm EXECUTE. Confirmar se o provisionamento é realizado por caminho privilegiado deliberado ou se há lacuna entre contrato de aplicação e grants.
- `iam.clear_tenant_context()` é SECURITY DEFINER e seu ACL contém `=X` (EXECUTE para PUBLIC). O corpo apenas limpa GUCs locais à transação; risco observado limitado, mas grant amplo é desnecessário e deve ser revisto.
- `iam.effective_permissions(uuid)` também possui EXECUTE para PUBLIC. O corpo exige membership ativa vinculada ao tenant do contexto validado; ainda assim, recomenda-se restringir PUBLIC e conceder apenas às roles consumidoras esperadas.
- Funções trigger `audit.reject_event_mutation()` e `iam.touch_updated_at()` têm ACL padrão (EXECUTE para PUBLIC), padrão PostgreSQL comum para trigger functions; não são endpoints SQL normais e devem permanecer vinculadas aos triggers previstos.

**Classificação:** inventário de privilégios efetivos concluído; duas concessões PUBLIC relevantes para revisão de least privilege (`clear_tenant_context`, `effective_permissions`) e uma possível lacuna de integração (`provision_membership`). Nenhuma alteração de ACL foi aplicada na fonte. Antes de corrigir, confirmar consumidores reais e testar grants/RLS em fixture descartável.

## Revisão das 41 policies RLS — rodada 5 (2026-11-05)

As 41 policies foram extraídas com `polpermissive`, comando, roles, `USING` e `WITH CHECK`.

- Todas as 41 policies estão em modo **PERMISSIVE**; não há policy RESTRICTIVE.
- As 20 tabelas RLS têm policy `iam_owner_access` para `iam_owner`, com `USING (true)` e `WITH CHECK (true)`.
- As policies de runtime/worker nas tabelas tenant-scoped usam `app_private.current_tenant_id()` em `USING` e `WITH CHECK`, com a exceção estrutural de `iam.identities`: `USING` verifica existência de membership no tenant atual e `WITH CHECK (true)`. A role runtime não possui INSERT/UPDATE nessa tabela na matriz efetiva consultada; worker tampouco possui DML nela.
- `audit.outbox` separa runtime (INSERT com tenant check) de worker (ALL com tenant check).
- `iam.tenants` compara `id` ao tenant atual; demais policies tenant-scoped comparam `tenant_id`.
- Não foi encontrada policy em `app_private.context_keys`, `iam.permissions` ou `iam.schema_migrations`, coerente com RLS desabilitado nessas tabelas.

**Limite de validação:** as expressões foram inspecionadas estaticamente; ainda não foram executados testes de leitura/escrita cross-tenant com `SET ROLE` e sessões separadas na fixture integral. Todas as policies serem permissive não é, por si só, falha: é necessário avaliar a união das policies por role/operação e os grants efetivos. RLS permanece PENDING até testes dinâmicos.

## Extração de definições do catálogo — rodada 6 (2026-11-05)

Consultas read-only ao catálogo da fonte oficial. Nenhuma linha de aplicação foi lida.

### Artefatos estruturais extraídos nesta rodada

- **Colunas:** definições por coluna consultadas em pg_attribute / pg_attrdef, incluindo nome, tipo resolvido, NOT NULL, default, identity e generated. Foram consultados os schemas iam, audit e app_private; total consolidado permanece 182 colunas.
- **Índices:** 63 definições CREATE INDEX extraídas via pg_indexes, incluindo índices parciais e únicos. Exemplos relevantes: app_private.context_keys_one_active_idx, audit.outbox_pending_idx, iam.invitations_pending_idx e iam.sessions_expiry_idx.
- **ENUMs:** 7 tipos e seus rótulos/ordem extraídos integralmente: api_key_status, audit_outcome, identity_status, invitation_status, membership_status, session_status, tenant_status.
- **View:** definição de iam.v_effective_membership_permissions extraída; owner iam_owner; opção security_invoker=true.
- **Triggers:** 12 definições extraídas via pg_get_triggerdef; todos habilitados (tgenabled='O'), incluindo os dois triggers append-only de audit.events e os dez triggers *_touch.
- **Sequences:** três objetos associados a audit.events, audit.outbox e iam.security_events; owner iam_owner.
- **Funções:** definições integrais de 9 funções extraídas em rodada anterior, incluindo corpo, SECURITY DEFINER, owner, proconfig e ACL.

### Constraints — segunda extração sem truncamento

Uma consulta filtrada por `contype <> 'n'` retornou as 101 constraints de integridade com definições completas e metadados de validação/deferrability: 24 CHECK, 33 FOREIGN KEY, 23 PRIMARY KEY e 21 UNIQUE. Todas as 101 estão `convalidated=true`; nenhuma é deferrable ou initially deferred. As 143 constraints NOT NULL foram contabilizadas separadamente por coluna (`attnotnull`). A contagem confere: 101 + 143 = 244.

### Limites da extração

- A tentativa agregada de retornar todas as 244 constraints foi truncada pela saída da ferramenta. Portanto, não classificar constraints como exportadas integralmente nesta rodada.
- A extração de colunas foi retornada por schema; a saída agregada da resposta foi parcialmente truncada no canal de ferramenta. O inventário agregado de 182 colunas permanece válido, mas é necessário persistir os resultados por lotes menores antes de montar o DDL final.
- pg_indexes fornece definições dos índices, mas não substitui pg_dump para preservar toda a semântica de constraints, ownership, ACLs, comments, dependências, extensões e estados de sequences.
- Não há, até aqui, um artefato de export DDL canônico completo, reproduzível e validado. O status do gate permanece PENDING.

## Próximas etapas obrigatórias

1. Extrair DDL estrutural fiel e sem dados da fonte: schemas, tipos, sequências, tabelas, constraints, índices, view, funções, triggers, policies, grants, owners e configurações RLS.
2. Verificar dependências e ordenação de criação; não copiar valores de `app_private.context_keys`, tokens, hashes, payloads ou dados de negócio.
3. Comparar o DDL extraído com `0001_initial_iam_schema.sql` e produzir relatório objeto-a-objeto.
4. Definir a estratégia de versionamento da baseline. Não reescrever migrations já aplicadas; avaliar baseline nova para banco vazio versus migration de reconciliação para instalações existentes.
5. Gerar fixture descartável a partir da baseline reconciliada, com roles e grants controlados.
6. Executar testes cross-tenant de SELECT/INSERT/UPDATE/DELETE, `USING`, `WITH CHECK`, `FORCE RLS`, views, funções SECURITY DEFINER e privilégios efetivos.
7. Vincular os resultados ao SHA exato da branch e do fixture.

## Limites e segurança

- Coleta realizada por consultas de catálogo somente leitura.
- Nenhum dado de aplicação foi exportado.
- Nenhum segredo foi lido ou copiado.
- Nenhum DDL foi executado na fonte `iam_database`.
- Nenhuma alteração foi feita em Development, Preview, Production, Auth0 ou Vercel.
- Os testes anteriores de HMAC ocorreram em database isolada com fixture mínima; não constituem evidência de RLS ou isolamento cross-tenant integral.

## Estado dos gates

| Gate | Estado |
|---|---|
| Fonte oficial confirmada | PASS |
| Inventário estrutural agregado | PASS |
| Divergência bootstrap × fonte identificada | PASS |
| Extração detalhada parcial do catálogo | PASS (escopo parcial; saída composta truncada) |
| Export DDL integral sem dados | PENDING |
| Baseline reconciliada e versionada | PENDING |
| Fixture integral fiel à fonte | PENDING |
| Testes RLS cross-tenant | PENDING |
| Privilégios efetivos por role | PENDING |
| Revisão de segurança da baseline | PENDING |
| Aplicação em qualquer ambiente persistente | NOT AUTHORIZED |

**Regra:** não declarar PASS para RLS, isolamento multi-tenant ou baseline integral até haver execução reproduzível em PostgreSQL descartável, vinculada ao SHA atual.


## Preparação do export reproduzível — rodada 7 (2026-11-05)

Foi adicionado `database/scripts/export-neon-schema.sh` na branch desta PR.

- Commit: `c7b0ac2dd523db25f6f441e4cd91e5909ee08c68`.
- O script exige cliente `pg_dump` 18+, TLS (`PGSSLMODE=require`) e `PGPASSFILE` protegido.
- Executa `pg_dump --schema-only` para `iam`, `audit` e `app_private`; não inclui linhas de tabelas.
- Mantém ownership e ACLs no arquivo para revisão; não provisiona roles.
- Recusa sobrescrever arquivo de saída existente e calcula SHA-256 após exportação.
- O conteúdo foi relido da branch após o commit.

### Verificação adicional de colunas

Consulta read-only independente em `pg_attribute` / `pg_class` confirmou novamente 182 colunas em 23 tabelas nos três schemas. A consulta retornou somente metadados de catálogo; para `app_private.context_keys.secret`, foi confirmada apenas a existência da coluna e seu tipo, sem ler qualquer valor.

### Estado do artefato

O script está versionado, mas **a execução de pg_dump ainda não ocorreu**. Nenhum arquivo SQL, checksum de dump, restauração ou comparação objeto-a-objeto foi produzido. Portanto, o gate de export DDL integral continua PENDING.


## Atualização do export — rodada 7 (2026-11-05)

A consulta read-only à fonte oficial confirmou o estado pós-migration:

- `pgcrypto` instalada no schema `public`, versão `1.4`;
- ledger contém exatamente um registro de `0001_context_key_hardening`;
- índice `app_private.context_keys_one_active_idx` presente;
- `app_private.current_tenant_id()` mantém `search_path=pg_catalog, app_private, iam`;
- nenhuma relação de aplicação no schema `public`.

O script `database/scripts/export-neon-schema.sh` foi atualizado no commit `133842cbc9e53ac61bfeaa27b9665225d189d002` para validar a presença de `pgcrypto` e declarar `CREATE EXTENSION IF NOT EXISTS pgcrypto WITH SCHEMA public` antes do DDL dos três schemas IAM. A extração de objetos de aplicação continua limitada a `iam`, `audit` e `app_private`; nenhum dado de tabela é exportado.

A declaração explícita da extensão é necessária porque a opção `pg_dump --extension` seleciona a extensão, mas não garante a inclusão de todas as dependências transitivas. O script não usa essa opção como substituto da declaração explícita.

**Status desta rodada:** correção do script versionada; execução local do script, geração de novo dump, checksum e restore integral pós-hardening ainda PENDING. O artefato `iam_database_schema.sql` existente continua sendo o dump anterior e não deve ser tratado como atualizado por este commit.

**Gate de merge:** permanece BLOCKED até gerar o artefato pós-hardening, restaurá-lo em banco descartável vazio e validar dependências, estrutura, ACLs, RLS e testes dinâmicos de isolamento.


## Diagnóstico do artefato local e endurecimento do export — rodada 8 (2026-11-05)

O conteúdo do arquivo local `iam_database_schema.sql` foi inspecionado pelo operador via `grep`. O resultado não encontrou nenhuma ocorrência de `CREATE EXTENSION`, `pgcrypto` ou `context_keys_one_active_idx`; a tabela `app_private.context_keys` está presente. O checksum informado para esse arquivo foi `958ef2755b90db2efea18949b7a5127e40894a573fb3730923c044692e5a19fb`.

A fonte oficial já havia confirmado `pgcrypto 1.4` no schema `public`, o índice parcial único `app_private.context_keys_one_active_idx` e o ledger da migration de hardening. Portanto, o arquivo local não demonstra a estrutura pós-hardening e não pode ser usado para restore de referência.

### Verificação em PostgreSQL temporário

Na branch Neon `schema-restore-validation-20261105` (ID `br-icy-smoke-b6yrud11`), database `iam_schema_restore_test`, executou-se somente consulta de catálogo como `iam_database_owner`:

- `pgcrypto`: versão `1.4`, schema `public`;
- índice: `CREATE UNIQUE INDEX context_keys_one_active_idx ON app_private.context_keys USING btree (active) WHERE (active IS TRUE)`;
- configuração da função: `search_path=pg_catalog, app_private, iam`.

Essa database temporária já continha o restore anterior; não é uma database vazia e esta consulta não valida o novo dump. Nenhum valor da tabela `app_private.context_keys` foi consultado.

### Correção do script versionado

O script `database/scripts/export-neon-schema.sh` foi atualizado para falhar de forma fechada:
- valida no catálogo da origem a presença e a definição do índice parcial único;
- valida o `search_path` de `app_private.current_tenant_id()`;
- rejeita o resultado de `pg_dump` se não contiver o índice e a configuração da função;
- valida no artefato final a declaração explícita de `pgcrypto` e a presença do índice antes de publicar o arquivo.

Commits desta rodada:
- `a34759356a005259b9919720d116746e1bf99a8e`: validação dos objetos no dump e no artefato final;
- `9ca334f7bc71040dd3532092938ef17ef5a67edf`: validação prévia dos objetos no catálogo da origem.

**Limite:** o script atualizado foi versionado, mas ainda não foi executado pelo operador com conexão à fonte e cliente `pg_dump` 18+. Não afirmar que o arquivo local foi regenerado nem que o novo dump foi restaurado. O próximo passo é executar o script atualizado, inspecionar o novo SHA e restaurar o artefato em database descartável vazia.



### Database descartável vazia preparada para o próximo restore

Foi criada na mesma branch temporária a database `iam_schema_restore_post_hardening` (ID `257484`), owner `iam_database_owner`. Consulta de catálogo imediatamente após a criação confirmou: zero relações nos schemas `iam`, `audit` e `app_private`; extensão `pgcrypto` ausente; índice de hardening ausente. Esta database está pronta para receber o novo dump, mas nenhum restore foi executado ainda.

## Contrato dinâmico de contexto e RLS — 2026-11-08

Foi adicionado o teste database/tests/runtime-rls-contract.sql e o restore descartável agora o invoca ao final de database/tests/restore-source-schema.sh.

O teste cria somente fixtures sintéticas dentro de uma transação PostgreSQL 18 descartável, assume iam_app_runtime e valida:
- contexto ausente retorna zero linhas em tenants, memberships e identities;
- assinatura HMAC-SHA256 válida resolve o tenant esperado;
- tenant A e tenant B enxergam apenas seus próprios registros, inclusive identities via membership;
- INSERT em organizations com tenant_id de outro tenant é rejeitado por RLS/WITH CHECK;
- assinatura adulterada, contexto expirado e validade superior a 300 segundos são rejeitados, limpando o contexto.

Todos os registros de teste terminam em ROLLBACK. Nenhum segredo persistente é usado; a chave é sintética e restrita ao teste. Nenhum comando é executado na origem Neon.

**Estado:** ADICIONADO, ainda não PASS. A execução no CI do novo HEAD é necessária para validar sintaxe, grants efetivos e comportamento. O contrato ainda não cobre membership/identity/tenant inativos, ausência/rotação de chave ativa, replay de nonce, nem comportamento com memberships reais do provider Neon.

A matriz completa e os gates separados estão em docs/database/iam-postgresql-test-matrix.md. Permanecem pendentes a comparação objeto-a-objeto com a fonte, a lineage da migration incremental e o teste concorrente com duas sessões independentes.


## Divergência confirmada entre o catálogo Neon e o dump versionado — 2026-11-08

Consulta read-only atual no Neon canônico confirmou para app_private.current_tenant_id(): SECURITY DEFINER=true, owner=iam_owner e search_path=pg_catalog, app_private, iam. O dump versionado em iam_database_schema.sql ainda declara search_path=pg_catalog, app_private, iam, public para essa função. Portanto, o dump não representa integralmente o estado pós-hardening observado na origem.

Foi endurecido database/tests/restore-source-schema.sh para falhar fechado se o restore não preservar SECURITY DEFINER, owner iam_owner e o search_path exato sem public. A expectativa é que o job detecte a divergência atual até que um export autenticado da fonte canônica atualize o artefato. Não alterar manualmente o dump para imitar a origem: regenerar pelo processo de export autorizado, validar checksum e comparar objeto-a-objeto.

O search_path de iam.set_tenant_context(...) ainda contém public na fonte e permanece um achado de hardening separado, documentado para correção/revisão futura; não foi alterado nesta etapa.


## Atualização de evidência e semântica de contexto — 2026-11-08

O job postgres-18-source-schema-restore passou anteriormente no SHA 50c0e71fa166158a80172dc9b27175982e439b22 para o restore estrutural: 23 tabelas, 1 view, 9 funções, 7 ENUMs, 12 triggers, 41 policies, 20 tabelas com RLS/FORCE RLS, owners, pgcrypto, índice parcial e ausência de linhas de aplicação. Isso não prova igualdade objeto-a-objeto com o catálogo Neon nem ACL efetiva no ambiente persistente.

O contrato runtime RLS foi adicionado ao script de restore. A primeira execução no SHA ad21cb5b4019199ed35a68ec56bcb9bba59793ac falhou no caso de assinatura adulterada porque o teste tentou exigir contexto vazio após um contexto válido de tenant A. A chamada com exceção, capturada pelo chamador, reverte os GUCs transaction-local modificados pela instrução; o contexto válido anterior pode ser restaurado. O teste agora limpa explicitamente o contexto antes de testar entradas inválidas. Novo CI no SHA subsequente é obrigatório; não classificar o contrato dinâmico como PASS com base no restore estrutural anterior.

A aplicação deve começar a operação de contexto em estado limpo. Se capturar falha de iam.set_tenant_context() dentro da transação, deve abortar a transação ou executar iam.clear_tenant_context() antes de continuar. Replay de nonce não está implementado/provado: o campo nonce integra o HMAC, mas não há evidência de armazenamento/consumo único ou rejeição de replay.

A fonte Neon canônica foi consultada por SELECT read-only em 2026-11-08: iam_migrator tem USAGE em iam, SELECT (não INSERT) em iam.schema_migrations e EXECUTE nas duas funções de migration; ambas são SECURITY DEFINER, owner iam_owner, com search_path restrito e sem PUBLIC EXECUTE. O ledger observado contém uma entrada de hardening cujo source SHA/checksum são históricos e não devem ser confundidos com o HEAD da PR.

**Pendências:** CI dinâmico no SHA atual; environment neon-schema-export e deployment branch policy não verificados por API disponível; export autenticado reproduzível; comparação objeto-a-objeto; ACL/ownership integral; replay/inativos/rotação de chave; branch Neon isolada com memberships reais; sequência canônica da migration inicial vs incremental; concorrência de lock com duas sessões independentes.


## Divergência confirmada entre dump versionado e origem — 2026-11-08

No SHA 51f9098a5a8b8506fae05909c9e289b799fea97a, os jobs quality e postgres-18-schema-contract passaram. O job postgres-18-source-schema-restore falhou no contrato do catálogo porque o dump contém app_private.current_tenant_id() como SECURITY DEFINER, owner iam_owner, com search_path pg_catalog, app_private, iam, public.

A consulta read-only executada na fonte Neon canônica confirmou que a função está hardened: SECURITY DEFINER=true, owner=iam_owner, search_path=pg_catalog, app_private, iam. Isso prova divergência do artefato versionado, não falha na fonte.

Não editar o dump manualmente para remover public: isso apagaria a proveniência do export e mascararia a divergência. Regenerar via pg_dump 18 autenticado contra a origem allowlisted, guardar SHA-256 e manifesto, restaurar novamente em database vazia e comparar objeto-a-objeto. O workflow atual executa apenas em push para main e o Environment neon-schema-export não foi verificável pelas ferramentas desta sessão; portanto, export autenticado permanece BLOCKED.

O contrato runtime RLS foi adicionado e agora separa os casos de contexto válido/inválido em statements distintos. Ainda não há PASS para ele porque o restore falhou antes de executar o teste dinâmico. O contrato de roles/migration passou neste SHA, mas não substitui o restore nem a equivalência com a fonte.


## CI pós-asserção de search_path — 2026-11-08

- HEAD testado: 51f9098a5a8b8506fae05909c9e289b799fea97a.
- CI run 42460672899: quality SUCCESS; Preview e Auth0 E2E SKIPPED.
- Database run 42460672895: postgres-18-schema-contract SUCCESS; postgres-18-source-schema-restore FAILURE.
- O restore reportou os demais totais esperados, mas falhou no novo gate porque o dump configura current_tenant_id com search_path=pg_catalog, app_private, iam, public. A consulta read-only no Neon canônico confirmou search_path=pg_catalog, app_private, iam.
- O contrato runtime HMAC/RLS não foi executado nesse run, pois o restore falhou antes da etapa de teste. O contrato dinâmico continua ADDED / NOT EXECUTED.
- O teste anterior 42460479806 chegou ao contrato runtime, mas falhou no caso de assinatura adulterada; os cenários foram separados em DOs independentes no HEAD seguinte, sem evidência verde ainda.
- Não alterar o dump manualmente. A correção deve vir de export autenticado da origem canônica, checksum e comparação integral objeto-a-objeto.


## Semântica de volatilidade do tenant resolver — 2026-11-08

O catálogo Neon read-only também confirma current_tenant_id() com provolatile=s (STABLE), embora leia GUCs de contexto alteráveis na transação e clock_timestamp(). Uma chamada posterior no mesmo statement pode observar resultado reaproveitado e não refletir a troca de tenant context. O teste de assinatura adulterada na PR #86 expôs esse comportamento quando executado depois de um contexto válido no mesmo bloco DO.

A migration 0001_context_key_hardening já consta no ledger Neon e não deve ser reescrita. A PR #85 adicionou proposta separada database/proposals/0002_context_resolver_volatility_hardening.sql para alterar a função para VOLATILE e retirar public do search_path de iam.set_tenant_context. O contrato de regressão troca tenant A → B dentro de um único bloco DO e verifica RLS. A proposta é executada somente no PostgreSQL 18 descartável; não foi aplicada ao Neon persistente.

A equivalência do dump, a correção da semântica da função, a lineage e a revisão permanecem gates independentes.


## Revalidação fonte × dump candidato — 2026-11-08 (HEAD bccf9b27496be0e04f11e4b5a5cfe46c27c62a7e)

Esta seção supersede as notas históricas anteriores que afirmavam que o dump atual ainda continha `public` no `search_path` de `app_private.current_tenant_id()`. No artefato atual (blob `1920b7946c88e624ec224917dc0f7742d2174904`), essa função está com `search_path=pg_catalog, app_private, iam`, igual ao catálogo Neon consultado. O `search_path` de `iam.set_tenant_context(...)` ainda inclui `public` tanto na origem quanto no dump; é um hardening separado, não uma divergência fonte × dump.

### Correção do alvo de restore CI

O job `postgres-18-source-schema-restore-manifest` anteriormente fazia checkout do dump histórico `79ae7dcf0f3523fab152f485fe699e90fb7ac6e9`, portanto seu PASS não era evidência de restore do candidato atual. No HEAD desta atualização:
- removido o checkout do SHA histórico;
- restore e geração do manifesto usam diretamente os arquivos do HEAD da PR;
- checkout do job `postgres-18-source-schema-restore` usa `persist-credentials: false`.

Evidência no SHA exato:
- CI run `42491683869`: `quality` SUCCESS; `preview-deployment` e `auth0-e2e` SKIPPED.
- Database run `42491683797`: `postgres-18-schema-contract`, `postgres-18-source-schema-restore` e `postgres-18-source-schema-restore-manifest` SUCCESS.
- Job `128765229352`: o dump candidato foi restaurado em PostgreSQL 18 descartável; dois manifests restaurados foram byte-idênticos; validator v1 passou; SHA-256 do manifesto restaurado `bd38ab0fb5316573e3cd2db5e7047f71201d2472082fb904a67c9b05f7dee600`.
- Job `128765229543`: 23 tabelas, 1 view, 9 funções IAM, 7 enums, 12 triggers, 41 policies, 20 tabelas FORCE RLS, ownership e pgcrypto; zero linhas de aplicação; contrato runtime signed-context/fail-closed/cross-tenant SELECT/INSERT passou.

### Fingerprints por seção: fonte canônica × restore candidato

Fonte: Neon project `twilight-fire-88497009`, branch `main` (`br-little-fire-b6adup9f`), database `iam_database`, PostgreSQL 18.6, consulta read-only com `iam_schema_export_reader`. O mesmo `schema-manifest.sql` e a mesma expressão de hash JSONB foram usados na fonte e no restore candidato.

Igualdade exata confirmada:
- schemas: 4;
- relations: 27;
- types: 7;
- policies: 41;
- triggers: 12;
- sequences: 3;
- aggregates: 0;
- IAM routines: 9;
- server_version_num.

Deltas que continuam explícitos:
- database identity e build string do servidor: diferença ambiental;
- database ACL: fonte 9 entradas; restore 5. Inclui grants provider-managed e grants operacionais de `iam_owner`/`iam_schema_export_reader`;
- default ACL: fonte 9; restore 0. As nove entradas observadas são defaults provider-managed em `public` (`cloud_admin` → `neon_superuser`);
- expanded object ACL: fonte 386; restore 383. As três entradas adicionais na fonte são USAGE de `iam_schema_export_reader` nos schemas `app_private`, `audit` e `iam`;
- extensions: duas em ambos; fingerprint diferente por atributos/ownership do ambiente;
- public extension routines: 37 em ambos; fingerprint diferente. As 37 rotinas públicas da fonte pertencem a `cloud_admin`; não são rotinas de aplicação IAM;
- roles: fonte 29; restore 21. O restore não representa integralmente os papéis provider-managed e as credenciais LOGIN provisionadas no ambiente;
- role memberships: fonte 26; restore 3. As memberships de logins e provider roles precisam de contrato separado;
- routines total: 46 em ambos, mas o fingerprint total diverge por `public`; o subconjunto das 9 rotinas IAM tem igualdade exata.

O catálogo fonte confirma `iam_app_runtime_login → iam_app_runtime` com `INHERIT TRUE / SET TRUE / ADMIN FALSE`, enquanto o contrato aprovado em `database/bootstrap/0000_iam_roles.sql` e `database/tests/0000_role_bootstrap_contract.sql` exige `INHERIT TRUE / SET FALSE / ADMIN FALSE`. Classificação: **DRIFT**. Não copiar a opção SET TRUE para a baseline e não executar GRANT/REVOKE/ALTER ROLE no Neon persistente sem revisão e gate de execução próprios.

A classificação detalhada e a decisão de normalização provider-managed estão registradas em `docs/database/schema-manifest-contract.md` (seção “Source-to-restore fingerprint comparison (2026-11-08)”).

### Gates restantes

- comparação integral objeto-a-objeto com política de normalização revisada e verificável;
- export autenticado reproduzível via workflow protegido em `main`, incluindo prova da proteção do GitHub Environment `neon-schema-export`;
- proveniência do ledger `iam.schema_migrations` por canal read-only separado; a role de export não possui SELECT e não terá privilégios ampliados automaticamente;
- revisão independente aprovada no SHA final.

Não marcar Ready for Review nem merge. Não executar DDL, GRANT, migration, seed, alteração de role ou dados no Neon persistente/Production.