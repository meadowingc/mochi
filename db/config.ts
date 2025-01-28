import { column, defineDb, defineTable } from "astro:db";

const User = defineTable({
  columns: {
    id: column.number({ primaryKey: true }),
    website: column.text(),
  },
});

const AnalyticsSite = defineTable({
  columns: {
    id: column.number({ primaryKey: true }),
    url: column.text(),
    userId: column.number({ references: () => User.columns.id }),
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
    User,
    AnalyticsSite,
    AnalyticsHit,
  },
});
