# IAM role bootstrap — revisão independente

**Status: PROPOSTA INTEGRADA NA CADEIA (PR #57 MERGED) / BOOTSTRAP EXECUTADO SOMENTE EM DEVELOPMENT SOB AUTORIZAÇÃO ESPECÍFICA / CREDENCIAIS LOGIN BLOCKED**

Este bootstrap é pré-requisito separado da migration `0001_initial_iam_schema.sql`. A migration 0001 não cria roles: exige sessão autenticada como `iam_migrator_login`, a cadeia de `SET ROLE` para `iam_migrator` e `iam_owner`, e privilégio `CREATE` no database.

## Topologia proposta

| Role | LOGIN | INHERIT | Finalidade |
|---|---:|---:|---|
| `iam_owner` | Não | Não | Owner dos schemas/objetos IAM; recebe somente `CREATE` no database |
| `iam_migrator` | Não | Não | Grupo de migração; pode assumir `iam_owner` por `SET ROLE` |
| `iam_migrator_login` | Sim | Não | Principal autenticável e sem atributos administrativos para executar migration |
| `iam_app_runtime` | Não | Sim | Grupo de runtime, sem `BYPASSRLS` ou atributos administrativos |
| `iam_app_runtime_login` | Sim | Sim | Principal de conexão da aplicação; herda runtime sem `SET ROLE` |

Memberships exatas:
- `iam_migrator_login → iam_migrator`: `INHERIT FALSE / SET TRUE / ADMIN FALSE`.
- `iam_migrator → iam_owner`: `INHERIT FALSE / SET TRUE / ADMIN FALSE`.
- `iam_app_runtime_login → iam_app_runtime`: `INHERIT TRUE / SET FALSE / ADMIN FALSE`.
- Nenhum membership direto `iam_migrator_login → iam_owner`.
- Nenhum `ADMIN OPTION` nas memberships concedidas aos principals IAM; nenhuma role IAM é membro de roles administrativas/provider-managed.

### Observação específica do Neon

No Development, o catálogo PostgreSQL mostrou cinco memberships adicionais cujo **member é `Iam-control-center_owner`**, cujo **grantor é `cloud_admin`** e que têm `ADMIN OPTION`. O Neon cria essas associações administrativas para o proprietário do database quando roles são criadas. Elas permitem a administração das roles pelo owner e **não são memberships concedidas a principals IAM** pelo bootstrap.

Por isso, o teste do grafo IAM deve contar as associações cujo membro é uma das cinco roles IAM e validar exatamente as três arestas aprovadas. Não deve contar as associações gerenciadas pelo Neon em que `Iam-control-center_owner` é o membro. Essas associações provider-managed não devem ser revogadas como correção do teste.

## Principal administrativo do bootstrap

O principal administrativo atual observado no projeto canônico é `Iam-control-center_owner`. O inventário read-only mostrou atributos administrativos, incluindo `CREATEDB`, `CREATEROLE`, `REPLICATION` e `BYPASSRLS`. Ele pode ser necessário para bootstrap, mas **não é runtime** e não deve ser colocado em `DATABASE_URL` da aplicação.

O SQL proposto exige que o principal seja uma sessão direta, não-superuser, com `CREATEROLE` e owner do database. A presença de `BYPASSRLS` no principal administrativo não é transferida às roles IAM criadas. O bootstrap falha se qualquer uma das cinco roles já existir; não tenta corrigir nem reutilizar roles parciais.

## Segurança e limites

1. O script é transacional, não idempotente e falha fechado. Se qualquer etapa falhar, PostgreSQL reverte as alterações da transação.
2. As duas roles LOGIN são criadas **sem senha**. Não há senha, hash, token ou secret no repositório. Credenciais devem ser emitidas separadamente por processo aprovado e armazenadas nos secrets/variáveis apropriados; nunca no Git.
3. `iam_owner` recebe somente `CREATE` no database. Não há `CREATEDB`, `CREATEROLE`, `BYPASSRLS` ou `SUPERUSER` nas roles IAM.
4. Não são concedidos privilégios de schema/tabela/sequence, policies RLS, permissões de aplicação, seeds, extensões ou ownership fora do necessário.
5. Runtime permanece **default-deny**. A role runtime não poderá acessar as tabelas IAM até que grants mínimos e políticas RLS sejam objeto de uma revisão separada.
6. O SQL não é chamado pela inicialização da aplicação, CI de deploy ou Vercel.
7. Não executar em Preview ou Production. O bootstrap foi executado em Development após autorização específica e preflight. O recovery point usado foi uma branch operacional copy-on-write, sem proteção contra exclusão e sem teste de restore; portanto, não equivale a snapshot restaurável comprovado.

## Testes

O workflow PostgreSQL 18 deve validar:
- atributos de cada role e ausência de atributos administrativos;
- grafo de memberships concedidas aos cinco principals IAM exatamente igual às três memberships aprovadas, sem associações adicionais; associações provider-managed em que o owner do database é o membro ficam fora desse grafo e são verificadas separadamente;
- ACL do database: sem CONNECT/TEMP para PUBLIC, CREATE apenas para `iam_owner`, CONNECT explícito para os dois LOGINs e sem TEMP para roles IAM;
- ausência de password hash no catálogo protegido `pg_authid` após bootstrap;
- opções exatas das três memberships;
- `CREATE` somente para `iam_owner` e `CONNECT` explícito para os dois logins;
- ausência de `CREATE` para runtime e logins;
- rejeição de segunda execução (bootstrap não idempotente);
- atomicidade/rollback de DDL de roles em uma transação descartável;
- senhas aleatórias efêmeras no runner e senha de serviço derivada do identificador da execução, sem credenciais fixas versionadas.

Esses testes validam o SQL em PostgreSQL 18 descartável. Não provam privilégios, memberships, autenticação ou comportamento RLS reais no Neon.

## Estado operacional após o bootstrap

1. Bootstrap aplicado somente em Development, no database `Iam-control-center`, a partir do arquivo `database/bootstrap/0000_iam_roles.sql` com blob SHA `e39ec33c5b72e697acca4cff5d6675d190ff8d90`.
2. As cinco roles IAM, as três memberships da topologia e os ACLs de database foram observados no catálogo após a execução.
3. As cinco memberships adicionais em que `Iam-control-center_owner` é membro foram identificadas como associações gerenciadas pelo Neon (`grantor=cloud_admin`); não foram removidas.
4. A validação inicial do teste falhou porque contava essas associações provider-managed. O teste foi corrigido para medir somente memberships concedidas aos cinco principals IAM. A correção ainda depende de CI no novo SHA.
5. Credenciais LOGIN não foram provisionadas. Não configurar `DATABASE_URL` de aplicação com o principal administrativo.
6. Não executar a migration `0001` até o CI atualizado, revisão da cadeia PR #57 → PR #80 e validação de autenticação do migrator estarem concluídos.
7. Preview e Production continuam bloqueados e não foram alterados.

**Auth0 permanece como IdP; Neon Auth não faz parte desta arquitetura.**


## Atualização de catálogo e preflight — 2026-11-08

A inspeção read-only mais recente do projeto Neon canônico (`twilight-fire-88497009`), branch `br-little-fire-b6adup9f`, database `iam_database`, identificou o proprietário efetivo como **`iam_database_owner`** (não `Iam-control-center_owner`). O grantor das memberships administrativas provider-managed é `cloud_admin`.

A topologia observada para o caminho de migração é:

- `iam_migrator_login → iam_migrator`: `INHERIT FALSE / SET TRUE / ADMIN FALSE`, grantor `iam_database_owner`.
- `iam_migrator → iam_owner`: `INHERIT FALSE / SET TRUE / ADMIN FALSE`, grantor `iam_database_owner`.
- `iam_database_owner → iam_migrator`: `INHERIT FALSE / SET FALSE / ADMIN TRUE`, grantor superuser `cloud_admin`.
- `iam_database_owner → iam_owner`: membership provider-managed `ADMIN TRUE / SET FALSE / INHERIT FALSE`, grantor `cloud_admin`, e uma aresta adicional `ADMIN FALSE / SET TRUE / INHERIT FALSE`, grantor `iam_database_owner`.

O owner também possui arestas provider-managed para as demais roles IAM. Essas arestas não são memberships concedidas a logins de aplicação e não devem ser removidas. O preflight da migration agora exige que o único grantee administrativo adicional seja o proprietário real do database, com opções exatas e grantor superuser; para `iam_owner`, aceita também somente a aresta SET-only emitida pelo próprio database owner. Qualquer outro grantee continua sendo rejeitado.

No PostgreSQL 18 descartável, o runner reproduz essas arestas do owner e valida que a migration aceita a topologia autorizada e rejeita memberships extras. Evidência do SHA `3debdfe2408374bdeeeed13657282b6f9fdd7200`: CI run `42443903792` SUCCESS e PostgreSQL 18 run `42443903806` SUCCESS. O novo teste adicional de simulação do owner está sendo executado em um SHA posterior; ainda não é PASS.

O bootstrap SQL não pode desabilitar a própria sessão administrativa. O runner bloqueia a conta temporária por uma conexão administrativa separada. Em qualquer bootstrap real, o operador deve executar e verificar esse bloqueio por um principal autorizado independente após o commit; a conta temporária nunca pode permanecer como credencial da aplicação.

**Limites:** toda a evidência acima é de catálogo read-only no Neon e de testes PostgreSQL descartáveis no CI. Nenhuma migration, DDL, GRANT ou seed foi executada no Neon persistente ou em Production. A lineage da migration incremental ainda depende da reconciliação com a baseline da PR #86.


## Divergência observada no runtime LOGIN — 2026-11-08

Consulta read-only ao catálogo da fonte Neon canônica encontrou:
- iam_app_runtime_login: LOGIN=true, INHERIT=false, SUPERUSER=false, BYPASSRLS=false;
- membership iam_app_runtime_login → iam_app_runtime: INHERIT=true, SET=true, ADMIN=false, grantor iam_database_owner;
- pg_has_role(..., 'USAGE')=true e pg_has_role(..., 'SET')=true.

Isso diverge do bootstrap versionado, que declara iam_app_runtime_login como LOGIN INHERIT e concede iam_app_runtime com INHERIT TRUE / SET FALSE / ADMIN FALSE. O login runtime consegue executar SET ROLE iam_app_runtime; não há evidência de que possa assumir iam_owner ou iam_migrator, portanto esta aresta isolada não equivale a escalada para owner, mas viola a regra documentada de não permitir SET ROLE no runtime.

Não alterar a origem automaticamente. Manter como DRIFT / DECISION REQUIRED: decidir se o contrato canônico deve ser o bootstrap versionado (NO SET para runtime) ou se a aresta SET-only atual é intencional. Antes de qualquer correção, verificar dependências de aplicação e executar um teste de regressão em branch descartável. A consulta não prova nem autoriza DDL/GRANT na Neon persistente.
