import { column, defineDb, defineTable } from "astro:db";

const AnalyticsSite = defineTable({
  columns: {
    id: column.number({ primaryKey: true }),
    url: column.text(),
  },
});

const AnalyticsHit = defineTable({
  columns: {
    pathname: column.text(),
    siteId: column.number({ references: () => AnalyticsSite.columns.id }),
  },
});

// https://astro.build/db/config
export default defineDb({
  tables: {
    AnalyticsSite,
    AnalyticsHit,
  },
});
