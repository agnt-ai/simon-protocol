/**
 * The SIMON application template: the basic server (simon-server) with a directory, recipient
 * policy, introductions, an owner window, webhooks, upload checks and an email bridge, each installed
 * through the server's extension API. The typed client for its API is `simon-app/client`.
 */
export { createApp, type App, type AppOptions } from './app.ts';
export { loadAppConfig, MODULES, type AppConfig, type ModuleName } from './config.ts';
export { MongoStore } from './store/mongo-store.ts';
export { connect } from './store/db.ts';
