/** Every factory-created instance (serveStdio may create a discarded discover probe). REA OwnedMcpServers. */
export class OwnedMcpServers<Server extends { close(): Promise<void> }> {
  readonly #servers = new Map<Server, () => Promise<void>>();
  #accepting = true;

  create(factory: () => Server): Server {
    if (!this.#accepting) throw new Error("MCP connection is closed");
    const server = factory();
    const close = server.close.bind(server);
    const ownedClose = async (): Promise<void> => {
      await close();
      this.#servers.delete(server);
    };
    this.#servers.set(server, ownedClose);
    server.close = ownedClose;
    return server;
  }

  /** Seal, then close; a failed close stays owned for retry. */
  closeAll(): Promise<PromiseSettledResult<void>[]> {
    this.#accepting = false;
    return Promise.allSettled([...this.#servers.values()].map((close) => Promise.resolve().then(close)));
  }
}
