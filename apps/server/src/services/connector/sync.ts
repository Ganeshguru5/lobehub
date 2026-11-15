import {
  hasMandatoryApproval,
  MANDATORY_APPROVAL_KEY,
  requiresSsrfSafeTransport,
  withMandatoryApprovalMark,
} from '@lobechat/const';
import { buildMcpToolMetadata, getMcpToolVisibility } from '@lobechat/const/mcpApp';

import type { ConnectorModel, DecryptedConnector } from '@/database/models/connector';
import type { ConnectorToolModel } from '@/database/models/connectorTool';
import type { ConnectorCredentials } from '@/database/schemas';
import {
  ConnectorMcpConnectionType,
  ConnectorStatus,
  ConnectorToolPermission,
} from '@/database/schemas';
import type { AuthConfig } from '@/libs/mcp';
import { inferCrudType } from '@/libs/mcp/utils';
import { resolveConnectorToolPermission } from '@/server/routers/lambda/_helpers/connectorToolPermission';
import { mcpService } from '@/server/services/mcp';
import { isMcpAppsEnabled } from '@/server/services/mcp/featureGate';

import { ensureFreshConnectorToken } from './tokens';

export interface ConnectorToolSyncContext {
  connectorModel: ConnectorModel;
  connectorToolModel: ConnectorToolModel;
}

/**
 * Build the MCP client connection params (with auth) from a connector row.
 *
 * Must match the params agent runs use (`buildConnectorManifests`): the MCP
 * client session is cached by these params, so a view's resource read and
 * tool calls only reach the session its tool ran on when they are equal.
 * `name` is therefore the stable identifier, not the editable display name.
 */
export const buildConnectorMcpParams = (
  connector: DecryptedConnector,
): Parameters<typeof mcpService.listRawTools>[0] => {
  if (connector.mcpConnectionType === ConnectorMcpConnectionType.stdio) {
    if (!connector.mcpStdioConfig) throw new Error('Missing stdio config');
    return {
      args: connector.mcpStdioConfig.args ?? [],
      command: connector.mcpStdioConfig.command,
      env: connector.mcpStdioConfig.env,
      name: connector.identifier,
      type: 'stdio',
    };
  }
  if (!connector.mcpServerUrl) throw new Error('Connector has no MCP server URL configured');
  const { auth, headers } = buildHttpAuthFromCredentials(connector.credentials);
  // Custom headers live in `metadata.customHeaders` (plaintext, independent of
  // the single-kind `credentials` column) so they can coexist with any auth
  // type. Merge them on top of any header-type credential headers (older rows
  // stored custom headers as a 'header' credential before this split).
  const customHeaders = connector.metadata?.customHeaders as Record<string, string> | undefined;
  const mergedHeaders = headers || customHeaders ? { ...headers, ...customHeaders } : undefined;
  return {
    auth,
    headers: mergedHeaders,
    name: connector.identifier,
    // On every request to it, the listing and tool calls alike
    ...(requiresSsrfSafeTransport(connector.metadata) ? { ssrfSafe: true } : {}),
    type: 'http',
    url: connector.mcpServerUrl,
  };
};

/**
 * Map stored credentials into the HTTP MCP client's auth config + custom headers.
 *
 * The MCP client only understands `bearer`/`oauth2` auth (both become an
 * `Authorization: Bearer …` header), so:
 * - bearer / apikey → bearer auth
 * - header          → passed through verbatim as request headers
 */
export const buildHttpAuthFromCredentials = (
  credentials: ConnectorCredentials | null,
): { auth?: AuthConfig; headers?: Record<string, string> } => {
  if (!credentials) return {};

  switch (credentials.type) {
    case 'oauth2': {
      // Only the access token: callers refresh it first (ensureFreshConnectorToken),
      // and the MCP client sends nothing else. Refresh metadata here would also
      // make these params, and so the cached MCP session, differ from the agent
      // runtime's for the same connector.
      return { auth: { accessToken: credentials.accessToken, type: 'oauth2' } };
    }
    case 'bearer': {
      return { auth: { token: credentials.token, type: 'bearer' } };
    }
    case 'apikey': {
      return { auth: { token: credentials.apiKey, type: 'bearer' } };
    }
    case 'header': {
      return { headers: credentials.headers };
    }
    default: {
      return {};
    }
  }
};

export interface ConnectorToolSyncOptions {
  /**
   * Drop the `auto` tools the server no longer lists, so they stop being
   * advertised: eval contracts, and an MCP install or reinstall, whose tool
   * list replaces the stored one as a plugin install replaced its manifest.
   * Approval and disabled rows stay as permission tombstones, so neither a later
   * listing nor the rollback of a failed reinstall can bring them back as `auto`.
   */
  pruneMissingAutoTools?: boolean;
}

/** After a sync: delete the connector's `auto` tools that `listedToolNames` no longer has. */
export const pruneMissingAutoConnectorTools = async (
  connectorToolModel: Pick<ConnectorToolModel, 'deleteToolsNotIn' | 'queryByConnector'>,
  connectorId: string,
  listedToolNames: string[],
): Promise<void> => {
  const tombstones = (await connectorToolModel.queryByConnector(connectorId))
    .filter((tool) => tool.permission !== ConnectorToolPermission.auto)
    .map((tool) => tool.toolName);
  await connectorToolModel.deleteToolsNotIn(connectorId, [...listedToolNames, ...tombstones]);
};

/** A tool the caller already listed (a desktop listing, a cloud server's market manifest). */
export interface ConnectorListedTool {
  description?: string;
  /**
   * A manifest tool's `humanIntervention` (cloud marketplace installs):
   * `required` / `always`, or rules or a dynamic config that can ask for
   * either, make a newly synced tool need approval. One that can ask for
   * `always` keeps it on every sync, since no approval mode waives it.
   */
  humanIntervention?: unknown;
  inputSchema?: Record<string, unknown>;
  toolName: string;
  /** The MCP tool's `_meta.ui.visibility`, when it declares one. */
  visibility?: string[];
}

/**
 * Store a tool list the caller already holds, without reaching the server,
 * and mark the connector `connected`. A tool synced before keeps the
 * permission it has.
 */
export const syncConnectorToolsFromList = async (
  connectorId: string,
  tools: ConnectorListedTool[],
  ctx: {
    connectorModel: Pick<ConnectorModel, 'updateStatus'>;
    connectorToolModel: Pick<
      ConnectorToolModel,
      'deleteToolsNotIn' | 'queryByConnector' | 'upsertMany'
    >;
  },
  options: ConnectorToolSyncOptions = {},
): Promise<{ toolCount: number }> => {
  const syncInputs = tools.map((t) => ({
    crudType: inferCrudType(t.toolName),
    // Applies to new tools only: a synced tool keeps the permission it has
    defaultPermission: resolveConnectorToolPermission(t.humanIntervention),
    description: t.description,
    inputSchema: t.inputSchema,
    // Refreshed on every sync, unlike the permission: an `always` the
    // manifest asks for stays mandatory whatever the permission is
    metadata: withMandatoryApprovalMark(buildMcpToolMetadata(t.visibility), t.humanIntervention),
    toolName: t.toolName,
  }));

  await ctx.connectorToolModel.upsertMany(connectorId, syncInputs);
  if (options.pruneMissingAutoTools) {
    await pruneMissingAutoConnectorTools(
      ctx.connectorToolModel,
      connectorId,
      syncInputs.map((tool) => tool.toolName),
    );
  }
  await ctx.connectorModel.updateStatus(connectorId, ConnectorStatus.connected);
  return { toolCount: syncInputs.length };
};

/**
 * Connect to a connector's MCP server, fetch its tool list, and sync it into
 * `user_connector_tools`. Refreshes the OAuth token first when needed, and
 * updates the connector status (`connected` on success, `error` on failure).
 *
 * Shared by the `syncTools` tRPC mutation and the OAuth callback so a connector
 * has its tools immediately after authorization — no client round-trip needed.
 */
export const syncConnectorToolsById = async (
  connectorId: string,
  /** `userId` decides the `mcp_apps` flag: with it on, view-only tools are listed too. */
  ctx: ConnectorToolSyncContext & { userId?: string | null },
  options: ConnectorToolSyncOptions & {
    /**
     * By tool name, the `humanIntervention` a marketplace manifest gives a tool
     * the server lists, which an MCP listing cannot carry (an HTTP marketplace
     * install). It applies as a listed tool's does in
     * {@link syncConnectorToolsFromList}. Without it (a refresh), a synced tool
     * keeps the mandatory approval it has.
     */
    humanInterventions?: ReadonlyMap<string, unknown>;
  } = {},
): Promise<{ toolCount: number }> => {
  let connector = await ctx.connectorModel.findById(connectorId);
  if (!connector) throw new Error('Connector not found');

  if (!connector.mcpServerUrl && connector.mcpConnectionType !== ConnectorMcpConnectionType.stdio) {
    throw new Error('Connector has no MCP server URL configured');
  }

  // Refresh the OAuth access token if it has expired before connecting.
  connector = await ensureFreshConnectorToken(connector, ctx.connectorModel);

  const mcpParams = buildConnectorMcpParams(connector);

  let rawTools: Awaited<ReturnType<typeof mcpService.listRawTools>>;
  try {
    // A server may list the tools only its views call just to a client
    // announcing MCP Apps; they are synced, and kept from the model, all the same
    rawTools = await mcpService.listRawTools(mcpParams, {
      mcpApps: await isMcpAppsEnabled(ctx.userId),
    });
  } catch (err) {
    await ctx.connectorModel.updateStatus(connectorId, ConnectorStatus.error);
    throw err;
  }

  // Only an install holds the marketplace's policy. Any other sync (the
  // background refresh, a manual one, the OAuth callback) has the listing
  // alone, which cannot tell whether a manifest's `always` still holds: the
  // tools it marked mandatory stay so, or auto-run would skip their approval.
  const keptMandatory = options.humanInterventions
    ? new Set<string>()
    : new Set(
        (await ctx.connectorToolModel.queryByConnector(connectorId))
          .filter((tool) => hasMandatoryApproval(tool.metadata))
          .map((tool) => tool.toolName),
      );

  const syncInputs = rawTools.map((t) => {
    const humanIntervention = options.humanInterventions?.get(t.name);
    // Kept even for view-only tools: a view's call must find the tool synced,
    // while the manifest build leaves it out of the model's tool list.
    const metadata = withMandatoryApprovalMark(
      buildMcpToolMetadata(getMcpToolVisibility(t._meta)),
      humanIntervention,
    );
    return {
      crudType: inferCrudType(t.name),
      defaultPermission: resolveConnectorToolPermission(humanIntervention),
      description: t.description,
      inputSchema: t.inputSchema as Record<string, unknown>,
      metadata: keptMandatory.has(t.name)
        ? { ...metadata, [MANDATORY_APPROVAL_KEY]: true }
        : metadata,
      toolName: t.name,
    };
  });

  await ctx.connectorToolModel.upsertMany(connectorId, syncInputs);
  if (options.pruneMissingAutoTools) {
    await pruneMissingAutoConnectorTools(
      ctx.connectorToolModel,
      connectorId,
      syncInputs.map((tool) => tool.toolName),
    );
  }
  await ctx.connectorModel.updateStatus(connectorId, ConnectorStatus.connected);

  return { toolCount: syncInputs.length };
};
