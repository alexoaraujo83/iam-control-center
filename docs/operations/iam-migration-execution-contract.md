# Contrato operacional de migrations PostgreSQL

**Status:** trilhas separadas: bootstrap limpo, histórico já aplicado na fonte e migrations incrementais futuras. Validação CI obrigatória no HEAD atual.
**Fonte canônica:** Neon twilight-fire-88497009 / branch br-little-fire-b6adup9f / database iam_database.
**Engine de teste:** PostgreSQL 18 descartável.
**Limite:** nenhuma instrução deste documento autoriza DDL, GRANT ou migration em Neon persistente ou Production.

## Modelo de principal e privilégio

| Principal | LOGIN | INHERIT | Responsabilidade |
|---|---:|---:|---|
| iam_migrator_login | Sim | Não | Identidade autenticada da conexão de migration |
| iam_migrator | Não | Não | Capacidade intermediária de migration; não é credencial |
| iam_owner | Não | Não | Owner de schemas/objetos IAM |
| iam_app_runtime_login | Sim | Não | Conexão de aplicação |
| iam_app_runtime | Não | Sim | Grupo de privilégios mínimos do runtime |
| iam_worker | Não | Sim | Principal de worker; fora do escopo de grants de migration |

A cadeia de migration é estritamente:
1. iam_migrator_login → iam_migrator: INHERIT FALSE / SET TRUE / ADMIN FALSE.
2. iam_migrator → iam_owner: INHERIT FALSE / SET TRUE / ADMIN FALSE.

A conexão inicia diretamente como iam_migrator_login; o preflight valida session_user, current_user, atributos administrativos e memberships antes de qualquer SET ROLE ou DDL. O login não herda privilégios de iam_owner; a capacidade de assumir o owner é explícita e transitiva. Nenhum principal IAM deve receber SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB ou REPLICATION.

### Memberships gerenciadas pelo Neon

O catálogo da fonte registra arestas provider-managed em que iam_database_owner é membro de roles IAM, concedidas por cloud_admin com ADMIN OPTION, sem INHERIT e sem SET. Para iam_owner, também foi observada uma aresta SET TRUE / INHERIT FALSE / ADMIN FALSE concedida pelo próprio iam_database_owner. Essas associações não são grants a runtime/login e não devem ser revogadas como parte do hardening.

O preflight da migration aceita somente as arestas exatas do database owner real e rejeita grantees inesperados. Não se deve presumir que o database owner do provedor é um principal IAM nem que seu nome é fixo entre projetos.

## Contrato do advisory lock

iam.acquire_migration_lock():
- é SECURITY DEFINER, owner iam_owner;
- usa search_path = pg_catalog;
- recebe EXECUTE de iam_migrator e iam_owner, sem PUBLIC;
- executa pg_advisory_xact_lock(721347, 18001);
- mantém o lock até o fim da transação que executou a função.

O runner CI deve provar contenção real, não apenas invocar a função: sessão A inicia transação, assume iam_migrator, adquire o lock e mantém a transação aberta; sessão B tenta adquirir o mesmo lock e só deve prosseguir depois do COMMIT de A. O teste não deve usar pg_advisory_unlock porque o lock é transacional.

## Contrato do ledger

iam.record_migration(text,text,text):
- é SECURITY DEFINER, owner iam_owner;
- usa search_path = pg_catalog, iam;
- recebe EXECUTE de iam_migrator e iam_owner, sem PUBLIC;
- valida formato do identificador, SHA-256 e source SHA;
- mesmo identificador + mesmo checksum é idempotente;
- mesmo identificador + checksum diferente deve abortar;
- grava session_user como principal executor, sem conceder DML direto no ledger ao login/migrator.

O teste CI deve demonstrar duas chamadas idênticas gerando uma única linha, checksum divergente sendo rejeitado e rollback removendo a linha sintética de teste.

## Privilégios observados na fonte (consulta read-only)

Snapshot consultado em 2026-11-08:

| Capacidade | iam_migrator |
|---|---:|
| USAGE em schema iam | true |
| SELECT em iam.schema_migrations | true |
| INSERT em iam.schema_migrations | false |
| EXECUTE iam.acquire_migration_lock() | true |
| EXECUTE iam.record_migration(text,text,text) | true |

As duas funções são SECURITY DEFINER e têm ACL explícita para iam_migrator e iam_owner, sem EXECUTE para PUBLIC. O login iam_migrator_login não herda privilégios de owner; ele usa a cadeia SET-only. Não conceder INSERT/UPDATE/DELETE direto no ledger nem privilégios em audit ou app_private por conveniência.

O ledger observado na fonte contém 0001_context_key_hardening, checksum 2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab, source SHA b80c98c51746e1d49039015eb649b9bdd735ef7f, execution role iam_migrator_login. Esse registro é evidência histórica do estado da fonte, não prova de que o HEAD atual da PR corresponde ao checksum registrado.

## Camadas de teste obrigatórias

1. **Bootstrap inicial limpo:** aplicar `database/bootstrap/0001_initial_iam_schema.sql` em database vazia separada; este artefato não pertence à sequência incremental e não é predecessor da migration histórica `0001_context_key_hardening`. Validar ownership, roles, RLS/FORCE RLS, default-deny, integridade cross-tenant e integridade de ator/audit.
2. **Histórico já aplicado na fonte:** `database/archive/source-applied-migrations/0001_context_key_hardening.sql` é o artefato histórico cujo ID `0001_context_key_hardening` consta no ledger Neon. Ele é executado somente em PostgreSQL descartável para testes de regressão; não integra a sequência de migrations pendentes e não deve ser reaplicado sobre a baseline exportada, que já contém seus efeitos.
3. **Preflight negativo:** rejeitar atributos administrativos e memberships adicionais antes de DDL; após cada rejeição, confirmar ausência do índice e do ledger entry.
4. **Concorrência:** duas sessões reais concorrendo pelo advisory transaction lock; a segunda deve bloquear até o COMMIT da primeira.
5. **Ledger:** idempotência, checksum mismatch, formato inválido e rollback.
6. **Baseline integral:** restaurar iam_database_schema.sql em PostgreSQL 18 descartável e verificar contagens, ownership, ACLs, extensões e ausência de dados.
7. **Isolamento tenant:** testes dinâmicos com tenants A/B, identidades/memberships sintéticas e roles reais; FORCE RLS/catalog counts não substituem os testes de acesso.
8. **Rollback operacional:** provar apenas em ambiente descartável. Não executar rollback experimental no Neon persistente.

## Evidências e limites atuais

- Neon main foi consultado somente por catálogo/SELECT.
- PostgreSQL 18 CI passou anteriormente para os contratos de role e migration no SHA 71c17ae648521b3f3b5d73689e756e981f6f9bfd; esse resultado não cobre os testes adicionais que acabam de ser incluídos.
- O restore integral do dump passou em PostgreSQL 18 descartável no SHA 50c0e71fa166158a80172dc9b27175982e439b22; não comprova igualdade objeto-a-objeto com a fonte Neon.
- Os testes independentes de bootstrap inicial, contenção concorrente do lock e ledger idempotence/mismatch foram adicionados à PR #85 e aguardam execução CI no novo SHA.
- Preview e Auth0 E2E foram SKIPPED nos workflows observados; não classificá-los como PASS.
- A sequência operacional é explícita: bootstrap limpo em database vazia; baseline operacional #86 restaurada como estado já existente; `0001_context_key_hardening` preservada apenas como artefato histórico em `database/archive/source-applied-migrations/`; proposals permanecem fora de `database/migrations/`. O dump DDL-only não contém o ledger, cuja proveniência continua sendo validada por canal read-only separado.

## Atualização de CI e correção da fixture — 2026-11-08

No primeiro CI após adicionar os contratos independentes, o job PostgreSQL 18 falhou ao iniciar a sessão A do teste concorrente: permission denied for schema iam. A causa foi uma fixture incompleta, não a ACL observada na fonte. A fixture criava as funções SECURITY DEFINER, mas não reproduzia os privilégios mínimos efetivamente observados para iam_migrator.

A fixture foi corrigida para refletir somente:
- USAGE no schema iam;
- SELECT no ledger iam.schema_migrations;
- EXECUTE em iam.acquire_migration_lock() e iam.record_migration(text,text,text);
- sem INSERT/UPDATE/DELETE direto no ledger;
- sem grants em audit ou app_private.

O contrato incremental agora verifica esses privilégios efetivos e a propriedade SECURITY DEFINER, owner, search_path e ausência de PUBLIC EXECUTE das duas funções. O job anterior confirmou que o teste de role-assumption continuou PASS, mas não executou os novos testes de lock/ledger nem o bootstrap inicial independente porque falhou antes deles.

O runner foi corrigido; os testes de contenção concorrente, ledger idempotente/checksum mismatch/rollback e bootstrap inicial em database separada aguardam novo CI no SHA posterior. Não reutilizar o PASS histórico de SHA anterior.


## Evidência CI dos contratos adicionais — 2026-11-08

**SHA exato:** 508aa6c80a8542ae90548a2558081cc242793792  
**Workflow database-schema-tests:** run 42460653768, job 128669066414 — SUCCESS.  
**Workflow CI:** run 42460653910, job quality 128669057005 — SUCCESS.  
**Preview deployment:** SKIPPED. **Auth0 E2E:** SKIPPED.

O log do job PostgreSQL 18 confirmou:
- 12 cenários negativos do preflight rejeitados antes de DDL, com ausência de índice e ledger entry após cada falha;
- lock A adquirido e lock B bloqueado por 3.934 ms até o COMMIT de A;
- ledger idempotente: duas chamadas iguais resultaram em uma linha; checksum divergente foi rejeitado; ROLLBACK removeu a linha sintética;
- bootstrap inicial 0001 executado em database limpa separada pela sessão autenticada iam_migrator_login e cadeia SET ROLE iam_migrator → iam_owner;
- contrato independente de ownership, default-deny, integridade cross-tenant e auditoria passou;
- migration incremental e contrato de context-key passaram na fixture source-derived.

Este PASS é exclusivo do SHA indicado. Não prova equivalência do fixture reduzido com a baseline integral Neon, nem RLS cross-tenant na fonte, nem execução em branch Neon. A PR permanece Draft até resolver lineage da migration e reconciliação integral da baseline.


## Proposta de hardening do resolver de tenant — 0002 (2026-11-08)

A consulta read-only da fonte Neon confirmou que a migration 0001_context_key_hardening já consta no ledger, aplicada por iam_migrator_login em 2026-11-05. Seu arquivo não deve ser reescrito.

A auditoria de função encontrou dois pontos para uma migration incremental posterior:
- app_private.current_tenant_id() é STABLE, apesar de ler GUCs de contexto que podem mudar durante a transação e consultar clock_timestamp(). Uma chamada posterior no mesmo statement pode reutilizar resultado anterior e devolver tenant obsoleto.
- iam.set_tenant_context(...) é SECURITY DEFINER e usa search_path=pg_catalog, app_private, iam, public, embora as referências de aplicação sejam qualificadas e public não seja necessário.

Foi criada database/proposals/0002_context_resolver_volatility_hardening.sql, fora da pasta de migrations ativas. A proposta altera current_tenant_id para VOLATILE e remove public do search_path de set_tenant_context. O teste database/tests/0002_context_resolver_volatility_contract.sql alterna tenant A → tenant B no mesmo bloco DO e valida visibilidade RLS atualizada.

O runner CI aplica essa proposta somente no PostgreSQL 18 descartável, após o fixture derivado e a migration 0001 de teste. A proposta não está aprovada para execução em Neon persistente/Production e não deve ser movida para database/migrations até resolver a lineage entre o bootstrap 0001 e a migration operacional 0001.


## Evidência de concorrência do advisory lock

O teste database/tests/migration-lock-ledger-contract.sh usa dois processos psql independentes e exige PIDs de backend distintos. A sessão A adquire o advisory transaction lock, grava um marcador dentro da transação e registra o evento pre-commit; a sessão B inicia enquanto A mantém o lock, aguarda a aquisição e então deve enxergar o marcador já commitado. O teste valida a ordem A_acquired < B_attempt < A_precommit_marker < B_acquired, a visibilidade do marcador pela sessão B, PIDs diferentes e bloqueio superior a 2 segundos. O marcador é removido com a database descartável e não altera o ledger de migrations.


## Limite da baseline schema-only e ledger — 2026-11-08

O dump iam_database_schema.sql é DDL-only. Ele restaura a tabela iam.schema_migrations, mas não transporta o registro 0001_context_key_hardening que existe na fonte Neon. O export reader iam_schema_export_reader não tem SELECT nesse ledger; o catálogo confirmou SELECT=false e DML=false. Logo, o dump não é, isoladamente, uma baseline de migration reproduzível.

A linha de ledger observada na fonte deve ser capturada por um canal read-only separado, aprovado e com provenance; não copiar manualmente para o dump nem conceder SELECT ao export reader sem aprovação. Até isso existir, não declarar a predecessor/lineage da migration 0001 estabelecida. A migration 0002 permanece em database/proposals e é executada somente na fixture descartável.


## Evidência final dos contratos no HEAD — 2026-11-08

**HEAD validado:** 09a71dd9ad2dc87d0a2771aa8a92271b3c2155b3  
**CI:** run 42461924302 — quality SUCCESS; Preview deployment SKIPPED; Auth0 E2E SKIPPED.  
**PostgreSQL 18:** run 42461924344, job 128672859800 — SUCCESS.

O log confirma, no mesmo job:
- preflight negativo: 12 cenários de role/membership rejeitados antes de DDL, sem índice nem ledger entry;
- proposta 0002 aplicada apenas na database descartável; current_tenant_id passou para VOLATILE e set_tenant_context perdeu public do search_path;
- contrato same-statement RLS: CTEs materializadas e dependentes trocaram tenant A → B e validaram visibilidade por tenant;
- advisory lock: backends distintos A=198/B=199; B aguardou 3.948 ms; A adquiriu antes da tentativa B e B só adquiriu após o marcador pre-COMMIT de A e a liberação transacional;
- ledger: chamadas idênticas idempotentes, checksum divergente rejeitado, rollback removeu a linha sintética;
- bootstrap inicial independente aplicado em database limpa pela sessão iam_migrator_login com SET ROLE iam_migrator → iam_owner; contrato de ownership, default-deny, tenant-integrity e audit passou.

O resultado comprova somente a fixture e o PostgreSQL 18 descartável nesse SHA. Não autoriza executar a proposta 0002 em Neon; não prova export/baseline integral nem resolve a colisão de lineage/versionamento. O P1 de migration lineage permanece aberto.


## Revalidação após atualização documental — HEAD 7254358e131274b9bf81e61ffd0bed5da6841f9a

O commit documental foi validado novamente:
- database-schema-tests run 42462002949, job 128673108502: SUCCESS;
- CI run 42462003007, job quality 128673108977: SUCCESS;
- mesmo-statement RLS A→B passou na proposta 0002;
- lock A/B com PIDs distintos, marcador inserido antes do COMMIT por A e observado por B após adquirir o lock; espera de 3.949 ms;
- ledger idempotência/checksum/rollback e bootstrap inicial independente PASS.

Preview deployment e Auth0 E2E continuaram SKIPPED.


### Registro exato do ledger na fonte Neon

SELECT read-only em main confirmou uma única linha:
- migration_id: `0001_context_key_hardening`
- checksum_sha256: `2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab`
- source_sha: `b80c98c51746e1d49039015eb649b9bdd735ef7f`
- execution_role: `iam_migrator_login`
- applied_at: `2026-11-05T04:16:49.492Z` (UTC)

Esses metadados são evidência de proveniência da fonte e devem ser preservados fora do dump DDL-only; não são prova de que o HEAD atual da PR executou essa migration.
