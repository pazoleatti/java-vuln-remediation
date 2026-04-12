#!/usr/bin/env node
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import * as z from "zod/v4";
import { resolve } from "node:path";

import { scanJavaProject } from "./scan.js";
import { osvQueryBatch } from "./osv.js";
import { suggestRemediation } from "./remediate.js";

function formatReportMarkdown(
  projectPath: string,
  reports: Awaited<ReturnType<typeof scanJavaProject>>["reports"]
): string {
  if (!reports.length) {
    return `Проект: \`${projectPath}\`\n\nПо данным OSV среди собранных зависимостей (Maven pom.xml и эвристика Gradle) **известных уязвимостей не найдено**.\n\nОграничения: только объявленные в pom/build.gradle зависимости; транзитивные зависимости не разрешены через Gradle/Maven полностью.`;
  }
  const lines: string[] = [
    `# Отчёт по уязвимым зависимостям`,
    ``,
    `Корень проекта: \`${projectPath}\``,
    ``,
    `| Зависимость | Текущая версия | Предлагаемая версия | Источник в репозитории |`,
    `|---|---|---|---|`,
  ];
  for (const r of reports) {
    const sug = r.suggestedVersion ?? "— (нет автоматического кандидата)";
    lines.push(
      `| \`${r.groupId}:${r.artifactId}\` | ${r.version} | ${sug} | \`${r.source}\` |`
    );
  }
  lines.push(``, `## Детали и комментарии к обновлению`, ``);
  for (const r of reports) {
    lines.push(`### ${r.coordinate}`, ``);
    lines.push(`**OSV:** ${r.vulnerabilities.map((v) => v.id).join(", ")}`, ``);
    if (r.suggestedVersion) {
      lines.push(`**Заменить на:** \`${r.groupId}:${r.artifactId}:${r.suggestedVersion}\``, ``);
    }
    lines.push(r.changeComment, ``);
  }
  return lines.join("\n");
}

const mcpServer = new McpServer({
  name: "java-vuln-remediation",
  version: "1.0.0",
  description:
    "Сканирует Java-проекты (Maven pom.xml, Gradle build.gradle/.kts), проверяет версии в OSV и предлагает более новые версии без записей OSV. Комментарии строятся по разнице идентификаторов OSV между версиями.",
});

mcpServer.registerTool(
  "scan_java_project",
  {
    description:
      "Найти в Java-проекте зависимости с известными уязвимостями (OSV), предложить версии без записей OSV и кратко описать, какие записи OSV снимаются при обновлении.",
    inputSchema: {
      projectPath: z.string().describe("Абсолютный или относительный путь к корню Java-проекта"),
      includeTestScope: z
        .boolean()
        .optional()
        .describe("Включать зависимости со scope=test (по умолчанию false)"),
      includeOptional: z
        .boolean()
        .optional()
        .describe("Включать optional=true (по умолчанию false)"),
    },
  },
  async ({ projectPath, includeTestScope, includeOptional }) => {
    const root = resolve(projectPath);
    const { coords, reports } = await scanJavaProject(root, {
      includeTestScope: includeTestScope ?? false,
      includeOptional: includeOptional ?? false,
    });
    const md = formatReportMarkdown(root, reports);
    const summary = `Проверено координат: ${coords.length}. С уязвимостями (OSV): ${reports.length}.`;
    return {
      content: [{ type: "text" as const, text: `${summary}\n\n${md}` }],
    };
  }
);

mcpServer.registerTool(
  "check_maven_dependency",
  {
    description:
      "Проверить одну Maven-зависимость (groupId:artifactId:version) в OSV и при необходимости предложить безопасную более новую версию на Maven Central.",
    inputSchema: {
      groupId: z.string(),
      artifactId: z.string(),
      version: z.string(),
    },
  },
  async ({ groupId, artifactId, version }) => {
    const batch = await osvQueryBatch([
      {
        package: { name: `${groupId}:${artifactId}`, ecosystem: "Maven" },
        version,
      },
    ]);
    const vulns = batch.results[0]?.vulns ?? [];
    if (!vulns.length) {
      return {
        content: [
          {
            type: "text" as const,
            text: `\`${groupId}:${artifactId}:${version}\` — по данным OSV **известных уязвимостей нет** (на дату запроса к OSV).`,
          },
        ],
      };
    }
    const rem = await suggestRemediation(groupId, artifactId, version, vulns);
    const lines = [
      `Зависимость: \`${groupId}:${artifactId}:${version}\``,
      `OSV: ${vulns.map((v) => v.id).join(", ")}`,
      rem.suggestedVersion
        ? `Предлагаемая версия: \`${groupId}:${artifactId}:${rem.suggestedVersion}\``
        : "Автоматически не удалось подобрать версию без записей OSV среди проверенных кандидатов.",
      "",
      "Комментарий к обновлению:",
      rem.changeComment,
    ];
    return { content: [{ type: "text" as const, text: lines.join("\n") }] };
  }
);

async function main() {
  const transport = new StdioServerTransport();
  await mcpServer.connect(transport);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
