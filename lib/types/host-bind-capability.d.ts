/**
 * What the installed webserver accepts as a bind address, plus the address
 * classes the LAN-bind decision needs (issue #1893).
 *
 * The managed LAN-bind block used to pin `host: '0.0.0.0'`. Since
 * `@deepseek-ai/dsh-host-webserver@0.2.1-rc.2` the webserver `Config` schema
 * rejects the unspecified (wildcard) address, so such a block is refused at
 * config validation and every later `dsh web` start fails. This module is the
 * one place that asks the installed package instead of assuming, and the block
 * planner reads its answer.
 *
 * The value import below is a devDependency of this package and stays external
 * in the published bundle (see the package tsdown config's libExternal): the
 * host process resolves it from the profile tree, which is exactly the module
 * it is about to compose. A host this module cannot interrogate is never
 * assumed permissive - every failure path answers "no wildcard", because an
 * unreadable package must not make the block pin a literal that refuses to
 * boot.
 *
 * @module wj-dsh-remote/host-bind-capability
 */
/** A schemastery-style schema: call the factory, throw on refusal. */
export type ConfigSchemaFactory = (value: unknown) => unknown;
/**
 * The schema factory of whatever module shape was loaded. The package exposes
 * `WebServer` both as a named export and as the default, and the default may
 * itself be a namespace, so the lookup walks those two links. Anything without
 * a callable `Config` is treated as an unusable shape.
 * @param moduleNamespace - the loaded module object (or any nested holder).
 * @returns the schema factory, or undefined when the shape is unusable.
 */
export declare function configSchemaOf(moduleNamespace: unknown): ConfigSchemaFactory | undefined;
/**
 * Validate the wildcard bind against one schema factory.
 * @param configOf - the schema factory to interrogate (undefined = unusable shape).
 * @returns true only when the schema accepts the wildcard bind.
 */
export declare function probeWildcardBindSupport(configOf: ConfigSchemaFactory | undefined): boolean;
/**
 * Whether the host this plugin runs on accepts the wildcard bind. Grounded in
 * the installed package's own schema, so it cannot drift away from the host
 * whatever the version is called; false when the package cannot be read.
 * @param configOf - schema factory override (test seam); by default the
 * installed package's own `WebServer.Config`.
 * @returns true only when the wildcard bind validates.
 */
export declare function wildcardBindSupported(configOf?: ConfigSchemaFactory): boolean;
/**
 * Validate one bind literal against one schema factory, the way the host
 * validates a profile's webserver row.
 * @param configOf - the schema factory to interrogate (undefined = unusable shape).
 * @param host - the bind literal to validate.
 * @returns true only when the schema accepts that literal on a fixed port.
 */
export declare function probeBindAccepted(configOf: ConfigSchemaFactory | undefined, host: string): boolean;
/**
 * Whether the running host accepts one bind literal. This is the rule the
 * managed block must follow instead of "is it a wildcard": the block REPLACES
 * the webserver row's config wholesale, so nothing else validates the CLI
 * `--host` that reaches it, and a literal the schema refuses bricks the next
 * start with a block that cannot be fixed from the settings card (issue #1893).
 * @param host - the bind literal to validate (an absent or empty value is never accepted).
 * @param configOf - schema factory override (test seam); by default the
 * installed package's own `WebServer.Config`.
 * @returns true only when the schema accepts the literal; false on every
 * unreadable shape, and never throws.
 */
export declare function bindAccepted(host: string | undefined, configOf?: ConfigSchemaFactory): boolean;
/**
 * Whether a bind value asks for every interface at once.
 * @param host - the bind value (absent while a recompose pass has not settled).
 * @returns true for the wildcard classes.
 */
export declare function isWildcardLiteral(host: string | undefined): boolean;
/**
 * Whether a bind value names this machine only, so no other device can dial
 * it: the loopback literals of the host package (127/8, ::1 and their mapped
 * forms), the `localhost` token the schema refuses as a literal, and an absent
 * bind. A hostname is treated by the host package's own verdict, not guessed.
 * @param host - the bind value (absent while a recompose pass has not settled).
 * @returns true when nothing off this machine can reach the listener.
 */
export declare function isLoopbackBind(host: string | undefined): boolean;
/**
 * The URL authority a concrete bind literal is expressed by. The host package
 * owns the canonical form (mapped loopback collapses to dotted quad, IPv6 gets
 * bracketed, a non-loopback zone id has no URL form).
 * @param host - a concrete bind literal.
 * @returns the URL host, or undefined when the literal has no URL form.
 */
export declare function bindUrlHostOf(host: string): string | undefined;
//# sourceMappingURL=host-bind-capability.d.ts.map