import { defineMiddleware } from "astro:middleware";

export function onRequest(context, next) {
  const { request } = context;

  // intercept data from a request
  // optionally, modify the properties in `locals`
  context.locals.title = "New title";

  // .. then use as
  // const data = Astro.locals;

  return next();
}

defineMiddleware;
