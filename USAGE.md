# SAST Remediation Pipeline — инструкция оператора

Запуск конвейера ремедиации уязвимостей корпоративного SAST из qwen cli, прямо в корне вашего Java-проекта. После прогона вы получаете отдельную ветку с по-одному коммитом на каждый фикс и markdown-отчёт с обоснованиями отклонений и инструкциями для регрессионного тестирования.

---

## 1. Что вы получите за один прогон

- Новую git-ветку `sast-fix/<commit>-<runId>` с N коммитами (по одному на каждое подтверждённое исправление).
- Файл `sast-report-<runId>.md` в корне рабочего дерева (намеренно **некоммиченный** — для вашего ревью, не для MR).
- Файл состояния `.sast-agent/state.json` со всеми решениями агентов.

После ревью отчёта и diff'ов вы сами пушите ветку и открываете MR.

---

## 2. Предусловия

| Что | Как проверить |
|---|---|
| Node.js ≥ 18 | `node --version` |
| qwen cli установлен | `qwen --version` |
| Доступ к корпоративному SAST API (URL + JWT) | спросите у безопасников |
| Внешний MCP `code-index` настроен в qwen | без него прогон будет fail-fast |
| Java-проект на git, рабочее дерево чистое | `git status` без правок |

---

## 3. Установка (делается один раз)

### 3.1. Сборка MCP-серверов

В **отдельном** каталоге (не в вашем рабочем проекте):

```bash
git clone https://github.com/Neovaryag/java-vuln-remediation.git
cd java-vuln-remediation
npm install
npm run build
```

Запомните абсолютный путь к этой папке — он понадобится в конфиге qwen. Далее везде `<MCP_DIR>` = этот путь.

### 3.2. Размещение agents / commands / skills

Чтобы slash-команда `/sast-run` и Named Subagents были доступны **в любом** вашем проекте, скопируйте конфигурацию qwen из MCP-репо в ваш домашний `~/.qwen/`:

**Linux / macOS:**
```bash
mkdir -p ~/.qwen/agents ~/.qwen/commands ~/.qwen/skills
cp -r <MCP_DIR>/.qwen/agents/*    ~/.qwen/agents/
cp -r <MCP_DIR>/.qwen/commands/*  ~/.qwen/commands/
cp -r <MCP_DIR>/.qwen/skills/*    ~/.qwen/skills/
```

**Windows (PowerShell):**
```powershell
$qwen = "$HOME\.qwen"
New-Item -ItemType Directory -Force -Path "$qwen\agents","$qwen\commands","$qwen\skills" | Out-Null
Copy-Item -Recurse -Force <MCP_DIR>\.qwen\agents\*    "$qwen\agents\"
Copy-Item -Recurse -Force <MCP_DIR>\.qwen\commands\*  "$qwen\commands\"
Copy-Item -Recurse -Force <MCP_DIR>\.qwen\skills\*    "$qwen\skills\"
```

> Альтернатива: положить эти три каталога в `.qwen/` корня **каждого** проекта, который будете чинить. Глобальный путь удобнее, если проектов много.

### 3.3. Конфигурация MCP-серверов в qwen

Откройте настройки qwen (`~/.qwen/settings.json`) и добавьте в блок `mcpServers` четыре сервера:

```json
{
  "mcpServers": {
    "sast-remediation-mcp": {
      "command": "node",
      "args": ["<MCP_DIR>/dist/servers/sast/index.js"],
      "env": {
        "SAST_API_BASE_URL": "https://sast.your-corp.example",
        "SAST_JWT_FILE": "/absolute/path/to/sast-jwt.txt"
      }
    },
    "sast-report-state-mcp": {
      "command": "node",
      "args": ["<MCP_DIR>/dist/servers/report/index.js"]
    },
    "repo-mcp": {
      "command": "node",
      "args": ["<MCP_DIR>/dist/servers/repo/index.js"]
    },
    "code-index": {
      "command": "...",
      "args": ["..."]
    }
  }
}
```

Замечания:

- `<MCP_DIR>` замените на абсолютный путь, на Windows — с двойными `\\` (`C:\\Users\\you\\java-vuln-remediation`).
- `SAST_API_BASE_URL` обязателен — без него SAST-сервер не стартует.
- `SAST_JWT_FILE` (путь к файлу с токеном) предпочтительнее `SAST_JWT` (инлайн): токен перечитывается при каждом вызове, ротация без рестарта qwen.
- `code-index` — внешний MCP, его конфиг возьмите из его собственной документации.
- Никаких `env` для `repo-mcp` и `sast-report-state-mcp` не требуется.

### 3.4. Проверка

Запустите `qwen` в любом каталоге и убедитесь, что `/sast-run` появляется в автодополнении slash-команд, а в списке tools видны `mcp__sast-remediation-mcp__*`, `mcp__sast-report-state-mcp__*`, `mcp__repo-mcp__*`, `mcp__code-index__*`.

---

## 4. Прогон в вашем проекте

### 4.1. Подготовьте проект

```bash
cd /path/to/your/java-project
git status              # должно быть clean
git fetch && git checkout <branch-to-fix>
```

Зафиксируйте git-хеш HEAD — он же должен быть `--commit` в SAST-сканировании:

```bash
git rev-parse HEAD
```

### 4.2. Запустите qwen

```bash
qwen
```

qwen стартует в интерактивном режиме в текущей директории.

### 4.3. Введите slash-команду

```
/sast-run --commit=<git-hash> --nexus=<dist-url> --jira=<JIRA-KEY> [--limit=<N>]
```

Параметры:

| Флаг | Обязательный | Описание |
|---|---|---|
| `--commit=<hash>` | да | Полный git-хеш коммита, на котором запущен SAST-скан. Должен совпадать с `HEAD` (или быть его предком). |
| `--nexus=<url>` | да | URL дистрибутива в Nexus, который сканировался. |
| `--jira=<KEY>` | нет (но обязательно для коммитов) | Тикет JIRA в формате `PROJ-1234`. Если не передать — оркестратор спросит перед фазой фикса. Без него коммитить нельзя. |
| `--limit=<N>` | нет | Положительное целое. Ограничивает число обрабатываемых уязвимостей за прогон. Подробнее ниже. |

### 4.4. Что происходит дальше

Оркестратор сам последовательно:

1. Запрашивает SAST-отчёт (`request_report` → polling `get_report`, до 20 минут).
2. Сидит все findings в `.sast-agent/state.json` со статусом `pending`.
3. Создаёт ветку `sast-fix/<commit>-<runId>` и переключается на неё.
4. Строит индекс кода (`code-index.build_deep_index`).
5. **Триаж**: для каждой уязвимости в порядке убывания severity запускается изолированный `triage-agent`. Вердикт — `confirmed` либо `rejected` с обоснованием.
6. **Фикс** (только после триажа): для каждой `confirmed` строго последовательно запускается `fix-agent` — правит код, делает один атомарный коммит с сообщением, ссылающимся на JIRA.
7. **Финальный отчёт**: оркестратор сам рендерит `sast-report-<runId>.md`.

Внутри прогона взаимодействия с вами **нет** (за исключением запроса JIRA-ключа, если вы его не передали). Все отказы и провалы фиксов уйдут в финальный отчёт — не пугайтесь, что что-то «молча отвалилось».

Прогон может длиться от минут до часов в зависимости от числа findings.

---

## 5. Параметр `--limit=<N>` — как использовать

### 5.1. Когда применять

- Большой отчёт (десятки/сотни findings), хочется сначала прогнать самые критичные и оценить качество фиксов агентом.
- Нужно вписаться в ограниченное окно времени.
- Дробить работу на несколько MR'ов (по 5–10 фиксов в каждом для удобства ревью).

### 5.2. Как работает

1. После сортировки списка `pending` (severity DESC → expirationDate ASC) берутся **первые N** записей.
2. Только они уходят в фазу триажа и далее в фикс.
3. Остальные **остаются в `pending`** в `.sast-agent/state.json` и попадают в финальный отчёт в секцию **Skipped (--limit)**.
4. `init_run` всегда сидит **все** findings — состояние полное, агрегаты в отчёте корректны.

Пример:

```
/sast-run --commit=abc123 --nexus=https://nexus/.../app.jar --jira=SEC-42 --limit=5
```

Из, скажем, 30 findings будут обработаны 5 топовых; в отчёте появится секция со списком 25 отложенных.

### 5.3. Как продолжить

Чтобы дотриажить остаток — **новый прогон** с тем же `--commit`/`--nexus` (повторный `init_run` идемпотентен по `(sastUuid, vulnerabilityId)`, статусы из прошлого прогона сохранятся, а оставшиеся `pending` будут обработаны):

```
/sast-run --commit=abc123 --nexus=https://nexus/.../app.jar --jira=SEC-42 --limit=5
```

Важно: `runId` будет новый → создастся **новая ветка** `sast-fix/abc123-<новый-runId>`. Фиксы из предыдущего прогона остаются в первой ветке. Если хотите все фиксы в одной ветке — мержите ветки сами после прогонов или не используйте `--limit`.

### 5.4. Граничные случаи

- `--limit=0`, отрицательное, нечисловое — abort на префлайте.
- `--limit=N` больше числа findings — лимит игнорируется неявно (обработаются все).
- Без `--limit` — обрабатывается весь отчёт.

---

## 6. Финальный отчёт `sast-report-<runId>.md`

Структура:

| Секция | Что внутри |
|---|---|
| **Header** | runId, commit, ветка-источник, ветка-фикс, reportUuid, JIRA, применённый `--limit`, гистограмма по severity, totals. |
| **Rejected** | По одной записи на отклонённый finding: id, локация, CWE, severity, **полное обоснование** triage-агента (verbatim — это аудит-артефакт). |
| **Fixed** | id, хеш коммита, краткое описание фикса, инструкция для регрессионного тестирования. |
| **Fix failed** | id, локация, CWE, причина провала. Это ваш ручной to-do list. |
| **Obsolete** | findings, которые в текущем дереве уже неактуальны. |
| **Skipped (--limit)** | Только если применялся `--limit` и есть отложенные. Список того, что не успели в этом прогоне. |
| **Anomalies** | Технические инциденты (агент не записал результат, сработал safety-net и т.п.). В норме пусто. |

---

## 7. После прогона

```bash
# 1. Прочитать отчёт
cat sast-report-<runId>.md

# 2. Посмотреть, что накоммитили
git log --oneline <branch-to-fix>..HEAD

# 3. Просмотреть diff'ы каждого фикса
git show <commit>

# 4. Если всё ок — пушим и открываем MR
git push -u origin sast-fix/<commit>-<runId>
```

Сам файл `sast-report-<runId>.md` **не** в коммитах ветки — это намеренно. Можно либо удалить его после ревью, либо приложить вручную к описанию MR.

---

## 8. Что делать, если

- **`/sast-run` не находится в qwen** — проверьте, что `~/.qwen/commands/sast-run.md` существует и qwen перезапущен.
- **«missing tool mcp__…»** — MCP-сервер не сконфигурирован в `~/.qwen/settings.json` или путь к `dist/servers/<name>/index.js` неверный. Проверьте `npm run build` в `<MCP_DIR>`.
- **«SAST_API_BASE_URL is required»** — добавьте `env` в `mcpServers.sast-remediation-mcp` в settings.json и перезапустите qwen.
- **«branch sast-fix/… already exists»** — был незавершённый прогон на тот же коммит. Удалите ветку (`git branch -D sast-fix/...`) или дайте новый `runId` (запустите команду заново — `runId` генерируется по timestamp).
- **dirty working tree на префлайте** — застешьте или закоммитьте локальные правки и запустите снова. Авто-стэша нет намеренно.
- **`build_deep_index` упал** — fail-fast, прогон не начнётся. Чините `code-index` MCP — без актуального индекса run unsound.
- **Один из фиксов провалился** — это нормально, прогон продолжается. Запись попадёт в **Fix failed** в отчёте, доделывайте руками.
- **Все фиксы провалились / отчёт пустой** — проверьте `Anomalies` в отчёте. Если там тоже пусто — вероятно, проблема в SAST-отчёте или в `code-index`; смотрите stderr qwen.

---

## 9. Безопасность

- JWT для SAST API живёт **только** внутри `sast-remediation-mcp` и никогда не уходит в контекст агента. `repo-mcp` и `code-index` ничего о токене не знают.
- `repo-mcp` пишет только в текущее рабочее дерево; в чужие репозитории не лезет.
- Финальный отчёт — локальный markdown-файл, без сетевых эффектов.
- Push в remote и открытие MR — **всегда вручную вами**, агенты этого не делают.
