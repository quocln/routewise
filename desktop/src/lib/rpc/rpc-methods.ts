import type { Export as ConfigExport } from "@/lib/api/config.gen";
import type {
  AccessClearResult,
  AccessListParams,
  AccessListResult,
  ActivityParams,
  ActivityResult,
  AddDomainParams,
  CheckHostParams,
  DNSCleanResult,
  Domain,
  HostCheck,
  ImportConfigParams,
  ImportConfigResult,
  ListDomainsParams,
  PrefsResult,
  PrefsSetParams,
  ProfileIDParams,
  ProfileImportParams,
  ProfileImportResult,
  ProfileInfo,
  ProfileUpdateParams,
  RemoveDomainParams,
  RouteEntry,
  SetDomainsParams,
  ProfileParams,
  ProfileResult,
  SetSettingsParams,
  SetTelemetryParams,
  SetVPNClientParams,
  Settings,
  StatusResult,
  SuccessResult,
  TelemetrySettings,
} from "@/lib/api/types.gen";

type Call<P, R> = { params: P; result: R };

/**
 * The helper's JSON-RPC methods with their params and result. `undefined`
 * params mean the method takes none. `rpc-methods.test.ts` fails to compile
 * when a method in the generated contract is missing here.
 */
export interface RpcMethods {
  "status.get": Call<undefined, StatusResult>;
  "debug.profile": Call<ProfileParams, ProfileResult>;
  "settings.get": Call<undefined, Settings>;
  "settings.set": Call<SetSettingsParams, Settings>;
  "routes.list": Call<undefined, RouteEntry[]>;
  "routes.check": Call<CheckHostParams, HostCheck>;
  "domains.list": Call<ListDomainsParams | undefined, Domain[]>;
  "domains.add": Call<AddDomainParams, SuccessResult>;
  "domains.remove": Call<RemoveDomainParams, SuccessResult>;
  "domains.set": Call<SetDomainsParams, SuccessResult>;
  "config.export": Call<undefined, ConfigExport>;
  "config.import": Call<ImportConfigParams, ImportConfigResult>;
  "vpn.setAllowed": Call<SetVPNClientParams, Settings>;
  "dns.clearCache": Call<undefined, SuccessResult>;
  "dns.clean": Call<undefined, DNSCleanResult>;
  "activity.list": Call<ActivityParams, ActivityResult>;
  "access.list": Call<AccessListParams, AccessListResult>;
  "access.clear": Call<undefined, AccessClearResult>;
  "prefs.get": Call<undefined, PrefsResult>;
  "prefs.set": Call<PrefsSetParams, SuccessResult>;
  "telemetry.get": Call<undefined, TelemetrySettings>;
  "telemetry.set": Call<SetTelemetryParams, TelemetrySettings>;
  "profiles.list": Call<undefined, ProfileInfo[]>;
  "profiles.import": Call<ProfileImportParams, ProfileImportResult>;
  "profiles.update": Call<ProfileUpdateParams, SuccessResult>;
  "profiles.remove": Call<ProfileIDParams, SuccessResult>;
  "profiles.connect": Call<ProfileIDParams, SuccessResult>;
  "profiles.disconnect": Call<ProfileIDParams, SuccessResult>;
}

export type RpcMethod = keyof RpcMethods;
export type RpcParams<M extends RpcMethod> = RpcMethods[M]["params"];
export type RpcResult<M extends RpcMethod> = RpcMethods[M]["result"];

/** The trailing arguments of `rpc()`: none, optional or required params. */
export type RpcArgs<M extends RpcMethod> = [RpcParams<M>] extends [undefined]
  ? []
  : undefined extends RpcParams<M>
    ? [params?: Exclude<RpcParams<M>, undefined>]
    : [params: RpcParams<M>];
