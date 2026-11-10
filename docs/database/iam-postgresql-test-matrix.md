# Matriz de testes da arquitetura IAM PostgreSQL

**Status:** BLOCKED — o contrato de roles/migration passou no SHA 51f9098a5a8b8506fae05909c9e289b799fea97a, mas o restore integral falhou porque o dump versionado mantém search_path antigo em current_tenant_id().
**Fonte estrutural:** Neon iam-database-delivery / iam_database, projeto twilight-fire-88497009, branch main (br-little-fire-b6adup9f).
**Regra de evidência:** PASS só é atribuído ao SHA exato em que o job correspondente terminou com sucesso. Restore descartável não prova equivalência com a origem Neon; RLS/FORCE RLS no catálogo não prova isolamento funcional.

## Decisões arquiteturais que os testes devem preservar

1. O banco não cria automaticamente tenant, identidade, membership ou permissões para uma identidade recém-autenticada. O vínculo de identidade com tenant/membership é explícito e persistido.
2. A aplicação usa uma role runtime sem SUPERUSER, BYPASSRLS, CREATEROLE, CREATEDB ou privilégios de owner/migrator.
3. O contexto de tenant não é confiável por ser apenas um GUC. app_private.current_tenant_id() valida um contexto assinado HMAC-SHA256 cujo payload canônico é tenant|identity|expires|nonce.
4. O contexto é fail-closed: exige tenant, identidade, expiração, nonce, assinatura, chave ativa, assinatura válida e tenant/identity/membership ativos. A expiração aceita no máximo 300 segundos.
5. Tabelas tenant-scoped devem ter RLS e FORCE RLS; testes de comportamento executam como iam_app_runtime, não apenas como owner/superuser.
6. Migrations são executadas por sessão direta iam_migrator_login, seguem a cadeia SET-only revisada, adquirem advisory transaction lock e registram checksum e source SHA no ledger na mesma transação.
7. Bootstrap de banco vazio, restore da baseline operacional e migrations incrementais são trilhas diferentes. Não inferir que a fixture reduzida de uma migration representa o schema integral.

## Cobertura automatizada

| Área | Teste / artefato | Cobertura comprovada ou pretendida | Estado |
|---|---|---|---|
| Restore estrutural | database/tests/restore-source-schema.sh | PostgreSQL 18 descartável; 23 tabelas, 1 view, 9 funções, 7 enums, 12 triggers, 41 policies, 20 tabelas RLS+FORCE, owners, pgcrypto, índice parcial e search_path hardened | FAIL no SHA 51f9098a5a8b8506fae05909c9e289b799fea97a: dump restaurado tem current_tenant_id search_path incluindo public; PASS histórico anterior não cobre este contrato atualizado |
| Contexto válido | database/tests/runtime-rls-contract.sql | HMAC válido e contexto resolvido para tenant A/B | ADICIONADO; CI pendente |
| Ausência de contexto | mesmo arquivo | SELECT de tenants, memberships e identities retorna zero linhas como runtime | ADICIONADO; CI pendente |
| Isolamento cross-tenant | mesmo arquivo | Tenant A vê apenas A; tenant B vê apenas B; identities filtradas pela membership | ADICIONADO; CI pendente |
| Escrita cross-tenant | mesmo arquivo | INSERT em organizations com tenant divergente é rejeitado por RLS/WITH CHECK | ADICIONADO; CI pendente |
| Assinatura adulterada | mesmo arquivo | assinatura inválida é rejeitada e o contexto permanece limpo | ADICIONADO; CI pendente |
| Expiração | mesmo arquivo | contexto expirado e validade superior a 300 segundos são rejeitados | ADICIONADO; CI pendente |
| Roles e memberships | database/tests/run.sh, role-assumption-contract.sql | atributos administrativos, arestas SET/INHERIT/ADMIN, fronteira owner, bootstrap lockout e cenários negativos antes de DDL | PASS histórico no SHA 71c17ae648521b3f3b5d73689e756e981f6f9bfd; conferir SHA atual após novo CI |
| Migration incremental | migration 0001_context_key_hardening.sql e 0001_schema_contract.sql | preflight, índice parcial, SECURITY DEFINER/search_path, ledger, checksum/source SHA e rollback de fixtures | PASS histórico no SHA acima; lineage permanece BLOCKED |
| Concorrência do lock | duas sessões psql independentes | PIDs distintos; sessão B aguarda A; T_B_attempt < T_A_precommit_marker < T_B_acquired, com B observando a linha commitada; ledger final sem entrada de migration de teste | PENDING — evidência independente ainda não registrada |
| Idempotência/checksum | runner de migration | mesma migration/checksum não duplica ledger; checksum divergente deve falhar fechado | Cobertura parcial; reforçar com testes explícitos |
| Estado de membership/identity/tenant | contrato de contexto | membership, identidade ou tenant inativos devem invalidar o contexto | PENDING no novo contrato dinâmico |
| Chave HMAC | contrato de contexto | ausência de chave ativa, chave curta, rotação e múltiplas chaves ativas | Parcial: constraint e índice único são verificados; comportamento de rotação/ausência deve ser testado |
| Auth0/OIDC | E2E externo | issuer, audience, assinatura/JWKS, expiração, claims namespaced e falhas de login/session | PENDING; jobs Auth0 E2E anteriores foram SKIPPED |

## Protocolo de concorrência obrigatório

Executar em uma branch Neon descartável ou PostgreSQL descartável com dois clientes independentes, nunca numa única conexão serializada:

- Sessão A: BEGIN, SET LOCAL ROLE iam_migrator, registrar PID e instante, adquirir iam.acquire_migration_lock(), aguardar e confirmar.
- Sessão B: iniciar depois de A, registrar PID/instante antes de chamar a mesma função; deve ficar bloqueada até A confirmar.
- Evidência: PIDs distintos; A adquiriu antes de B tentar; o evento A_PRECOMMIT_MARKER é gravado por A dentro da transação; B só adquire depois do lock e lê o marcador já commitado (count=1); ambas as transações encerraram; ledger permaneceu inalterado.
- Não marcar PASS com apenas pg_sleep em uma única sessão ou logs sem correlação temporal entre os dois clientes.

## Limites e pendências

- O contrato dinâmico adicionado é executado no restore PostgreSQL descartável. Ele não executa DDL nem dados na fonte Neon.
- O teste ainda não comprova comportamento em branch Neon isolada com as memberships/provider grants reais.
- A fixture iam_database_context_key_baseline.sql é reduzida e serve apenas à migration incremental. Não é a baseline canônica.
- O bootstrap `database/bootstrap/0001_initial_iam_schema.sql` é exclusivo de database vazia e está fora de `database/migrations/`. O artefato histórico `0001_context_key_hardening` permanece em `database/archive/source-applied-migrations/` porque já consta no ledger Neon. A baseline #86 é estado operacional já pós-hardening; não reaplicar a migration histórica sobre ela. Propostas futuras permanecem em `database/proposals/` até revisão e versionamento próprios.
- Não ler nem versionar secrets, chaves HMAC, hashes, JWTs, payloads ou linhas reais de negócio.
- Não aplicar migration, DDL, GRANT, seed ou alteração de dados em Neon persistente/Production como parte destes testes.


### Drift detectado na comparação fonte × dump

- Neon canônico (consulta de catálogo read-only em 2026-11-08): app_private.current_tenant_id() é SECURITY DEFINER, owner iam_owner, search_path=pg_catalog, app_private, iam.
- Dump versionado atual: a mesma função ainda declara search_path=pg_catalog, app_private, iam, public.
- O restore contract agora exige a configuração endurecida exata e deve falhar até que o dump seja regenerado da fonte canônica aprovada.
- Não editar o dump manualmente nem atribuir PASS ao restore anterior como prova de equivalência. O PASS anterior só validou a versão histórica do artefato e os objetos que aquele teste verificava.


## Atualização de semântica do contexto — 2026-11-08

O primeiro CI do contrato dinâmico no SHA anterior falhou no caso de assinatura adulterada porque o teste tentou validar a ausência de contexto depois de já ter estabelecido um contexto válido para tenant A. Em PostgreSQL, quando a chamada que altera GUCs transaction-local termina com exceção e a exceção é capturada pelo chamador, os efeitos da instrução com erro são revertidos; o contexto válido anterior pode permanecer ativo.

O teste foi corrigido para chamar iam.clear_tenant_context() e confirmar estado vazio antes de testar assinatura adulterada, expiração e TTL acima de 300 segundos. O novo SHA precisa passar o restore + runtime RLS para que esses casos sejam PASS.

**Implicação operacional:** o consumidor deve iniciar a operação de contexto em estado limpo. Se capturar uma exceção de iam.set_tenant_context() dentro da mesma transação, deve abortar a transação ou chamar iam.clear_tenant_context() antes de continuar; não deve presumir que a tentativa inválida removeu um contexto válido anterior. A tentativa inválida não deve ser usada como mecanismo de troca de tenant.

Replay de nonce continua PENDING: o payload inclui nonce, mas o contrato atual não demonstra persistência/consumo único do nonce nem rejeição de replay. Não afirmar proteção anti-replay até existir implementação e teste concorrente apropriados.


## Resultado de restore e comparação com a origem — 2026-11-08

No SHA 51f9098a5a8b8506fae05909c9e289b799fea97a:
- CI quality: SUCCESS.
- postgres-18-schema-contract: SUCCESS.
- postgres-18-source-schema-restore: FAILURE no contrato catalog.

O erro foi reproduzido no restore descartável: o dump contém app_private.current_tenant_id() como SECURITY DEFINER, owner iam_owner, porém com search_path pg_catalog, app_private, iam, public. O contrato exige a configuração pós-hardening sem public.

Consulta read-only atual à fonte Neon canônica confirmou app_private.current_tenant_id() SECURITY DEFINER, owner iam_owner e search_path=pg_catalog, app_private, iam. Portanto, a origem está hardened e o arquivo iam_database_schema.sql versionado está desatualizado; não corrigir o dump por edição manual nem declarar equivalência. É necessário regenerar o dump com pg_dump 18 autenticado contra a fonte allowlisted, preservar checksum/manifesto, restaurar novamente e comparar objeto-a-objeto.

O workflow neon-schema-export está configurado apenas para push em main e o Environment neon-schema-export/deployment branch policy não foi verificado por ferramenta disponível nesta sessão. Não foi executado export autenticado nesta rodada. O gate de baseline permanece BLOCKED até existir artefato exportado da fonte, com provenance e checksum verificáveis.


## Resultado de CI — 2026-11-08 (HEAD 51f9098a5a8b8506fae05909c9e289b799fea97a)

- CI run 42460672899: quality SUCCESS no HEAD da PR; preview-deployment e auth0-e2e SKIPPED.
- Database run 42460672895: postgres-18-schema-contract SUCCESS; postgres-18-source-schema-restore FAILURE.
- Causa exata: o restore restaurou 23 tabelas, 1 view, 9 funções, 7 enums, 12 triggers, 41 policies, 63 índices, 20 tabelas com RLS/FORCE RLS, ownership e pgcrypto; porém app_private.current_tenant_id() no dump foi restaurada com config search_path=pg_catalog, app_private, iam, public, enquanto o catálogo Neon atual confirma search_path=pg_catalog, app_private, iam. O novo gate falhou corretamente e bloqueou o contrato dinâmico seguinte.
- O primeiro run do contrato dinâmico (42460479806) falhou no caso de assinatura adulterada porque os casos estavam agrupados em um único bloco DO. A implementação foi separada em DOs independentes; ainda não há execução verde do contrato dinâmico, pois o restore agora falha antes de invocá-lo.
- Estado: catálogo/restore atual BLOCKED por drift real do dump; contrato dinâmico ADDED / NOT YET EXECUTED; não declarar PASS.
- Próximo passo seguro: export autenticado via workflow aprovado da fonte Neon canônica, regenerar artefato sem edição manual, validar checksum e comparação objeto-a-objeto; depois reexecutar restore e contrato runtime.


### Precisão da instrumentação do lock

O teste grava migration_lock_probe dentro da transação A antes do COMMIT. A sessão B tenta o mesmo advisory transaction lock, só prossegue depois da liberação transacional e então consulta o marcador. O teste exige count=1, PIDs distintos, ordem A_LOCK_ACQUIRED < B_LOCK_ATTEMPT < A_PRECOMMIT_MARKER < B_LOCK_ACQUIRED e espera mensurável (>2 s). A visibilidade do marcador por B prova que A já commitou; não depende de um SELECT pós-COMMIT em A, que poderia sofrer corrida de observabilidade.


## Drift de membership do runtime na fonte — 2026-11-08

A consulta read-only da fonte Neon encontrou iam_app_runtime_login com rolinherit=false e membership para iam_app_runtime com INHERIT=true, SET=true, ADMIN=false (grantor iam_database_owner). pg_has_role(..., 'USAGE') e pg_has_role(..., 'SET') retornam true.

O bootstrap versionado define iam_app_runtime_login como LOGIN INHERIT e concede a membership runtime com INHERIT TRUE / SET FALSE / ADMIN FALSE. A origem, portanto, diverge do contrato do bootstrap. A membership observada não concede acesso a iam_owner/migrator, mas permite SET ROLE iam_app_runtime e contraria o requisito documentado de runtime sem SET ROLE.

Estado: DRIFT / DECISION REQUIRED. Não normalizar com GRANT/REVOKE/ALTER ROLE automaticamente. Definir o contrato esperado, validar dependências e testar a alteração em branch descartável antes de qualquer execução persistente.


## Achado adicional de semântica do contexto — 2026-11-08

Consulta read-only ao catálogo Neon canônico confirmou:
- app_private.current_tenant_id(): provolatile = s (STABLE), SECURITY DEFINER, owner iam_owner, search_path endurecido pg_catalog, app_private, iam.
- iam.set_tenant_context(...): provolatile = v (VOLATILE), SECURITY DEFINER, owner iam_owner, search_path ainda inclui public.

Como current_tenant_id() lê GUCs de contexto mutáveis na transação e clock_timestamp(), STABLE pode permitir reutilização de resultado dentro de um statement quando a aplicação alterna tenant context. O CI anterior da PR #86 falhou no teste de assinatura adulterada após uma chamada válida no mesmo DO, o que expôs essa semântica; o teste original foi separado para continuar validando cada caso, mas isso não substitui a correção da função.

A PR #85 adicionou a proposta fora da pasta de migrations ativas: database/proposals/0002_context_resolver_volatility_hardening.sql. Ela altera current_tenant_id para VOLATILE e remove public do search_path de set_tenant_context. O contrato database/tests/0002_context_resolver_volatility_contract.sql alterna tenant A → B no mesmo bloco DO e verifica RLS sem dados cruzados. O runner executa a proposta somente em PostgreSQL 18 descartável, nunca em Neon persistente.

A migration 0001 já está registrada no ledger Neon; não reescrever seu arquivo/checksum. A proposta 0002 continua pendente de lineage, revisão, CI exato e gate próprio antes de qualquer execução persistente.


## Read-only preflight da role de export — 2026-11-08

A role iam_schema_export_reader existe na fonte canônica:
- LOGIN=true, INHERIT=false, SUPERUSER/BYPASSRLS/CREATEROLE/CREATEDB/REPLICATION=false;
- CONNECT em iam_database=true;
- USAGE em iam, audit, app_private e public=true;
- CREATE nesses schemas=false;
- nenhuma membership concedida ao reader;
- a única aresta relacionada é iam_database_owner → iam_schema_export_reader, concedida por cloud_admin com ADMIN=true, INHERIT=false e SET=false (provider-managed; não é capacidade do reader).

O perfil catalogado tem grants mínimos para leitura de metadados sem acesso a dados. A capacidade real de executar pg_dump 18 schema-only ainda NÃO foi comprovada; é necessário executar o workflow e validar a autenticação. Não presumir que NEON_SCHEMA_EXPORT_URL esteja configurado com essa role, pois seu valor não foi lido.


## Proveniência do ledger — dado de controle fora do schema-only dump

O dump schema-only cria a estrutura iam.schema_migrations, mas não exporta suas linhas. A fonte Neon contém o registro 0001_context_key_hardening (checksum/source SHA documentados neste arquivo); um restore apenas de DDL fica com ledger vazio e não representa sozinho o estado de migrations já aplicado.

O catálogo confirmou que iam_schema_export_reader tem USAGE em iam, mas não tem SELECT em iam.schema_migrations (nem INSERT/UPDATE/DELETE). Portanto, o workflow atual não consegue obter o ledger histórico com a role de export least-privilege. Não ampliar grants automaticamente.

Antes de declarar uma baseline reprodutível:
1. definir um canal read-only separado e aprovado para capturar apenas os campos de controle do ledger (migration_id, checksum_sha256, source_sha, execution_role, applied_at), sem dados de aplicação;
2. preservar o resultado como artefato/manifesto com checksum e provenance;
3. restaurar o DDL em database descartável e verificar explicitamente que o ledger está vazio antes de aplicar o manifesto sintético de baseline;
4. testar que o ledger restaurado corresponde à origem e que a migration seguinte parte do predecessor correto.

Estado: BLOCKED / MIGRATION LINEAGE. O ledger não pode ser inventado, copiado manualmente para o dump nem tratado como dado de aplicação.


## Hardening do workflow de export

O script export-neon-schema.sh agora falha fechado se a conexão não for diretamente iam_schema_export_reader. Valida atributos LOGIN/NOINHERIT sem privilégios administrativos, ausência de memberships concedidas ao reader, a única aresta provider-managed inversa exata do database owner, CONNECT sem CREATE/TEMP, USAGE sem CREATE nos schemas e ausência de SELECT/DML no ledger. O workflow também identifica explicitamente no manifest que migration_ledger_rows não é exportado.

Isso protege o export contra secret apontando para iam_migrator_login, iam_database_owner ou outra role privilegiada. O código foi atualizado, mas não foi executado contra a fonte nesta sessão porque o workflow está restrito a push em main e o Environment/secret não é verificável pelas ferramentas disponíveis.


A verificação de objetos também confirmou zero privilégios SELECT/INSERT/UPDATE/DELETE em todas as tabelas, views, materialized views e sequences de iam, audit e app_private. O export script agora exige essa ausência de acesso a dados, além de negar CREATE/TEMP; o papel é limitado à leitura de metadados/catálogos para pg_dump --schema-only.


### Registro de origem observado

| Campo | Valor |
|---|---|
| migration_id | `0001_context_key_hardening` |
| checksum_sha256 | `2447395628fa0f1230abd95eb522e5b45d1baea1208c9c21b20346a10718fbab` |
| source_sha | `b80c98c51746e1d49039015eb649b9bdd735ef7f` |
| execution_role | `iam_migrator_login` |
| applied_at (UTC) | `2026-11-05T04:16:49.492Z` |

Registro obtido por SELECT read-only em `main`. É metadado de controle; não está contido no dump schema-only.


### Validação direta da identidade export reader — 2026-11-08

Conexão read-only via Neon MCP usando explicitamente `role_name=iam_schema_export_reader` foi bem-sucedida. `current_user=session_user=iam_schema_export_reader`, database `iam_database`; LOGIN=true, NOINHERIT, sem SUPERUSER/BYPASSRLS/CREATEDB/CREATEROLE/REPLICATION; CONNECT=true; CREATE/TEMP=false; USAGE=true e CREATE=false em iam/audit/app_private; SELECT no ledger=false; nenhum table/sequence data privilege; nenhuma membership concedida ao reader; exatamente uma aresta provider-managed inversa do database owner, SET=false/INHERIT=false/ADMIN=true.

Isso valida a identidade e os predicados do preflight diretamente na origem, sem ler o secret GitHub nem executar DDL. Ainda não prova que NEON_SCHEMA_EXPORT_URL usa a mesma role nem que pg_dump 18 schema-only funciona com esse conjunto de privilégios; essas duas etapas dependem do workflow real.


## Revalidação do HEAD atual — 9822074c38051dee88d50d8e4de4763fcf05b3f0

- CI run 42462385742: quality SUCCESS; Preview/Auth0 E2E SKIPPED.
- Database run 42462385689: schema-contract SUCCESS; source-schema-restore FAILURE.
- O restore reproduziu o mismatch de search_path de app_private.current_tenant_id() com public presente no dump e ausente na origem.
- O runtime RLS não executou porque o restore falhou antes.
- O preflight do export reader foi validado por conexão read-only direta, mas pg_dump 18 e o Environment secret continuam sem execução/verificação.

Status do gate: BLOCKED; não declarar baseline equivalente.
