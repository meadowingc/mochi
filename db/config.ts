import { column, defineDb, defineTable } from "astro:db";

const User = defineTable({
  columns: {
    id: column.number({ primaryKey: true }),
    name: column.text(),
    email: column.text(),
    createdAt: column.date(),
  },
});

const Site = defineTable({
  columns: {
    id: column.number({ primaryKey: true }),
    userId: column.number({ references: () => User.columns.id }),
    createdAt: column.date(),
    url: column.text(),
  },
});

const Hit = defineTable({
  columns: {
    siteId: column.number({ references: () => Site.columns.id }),
    path: column.text(),
    date: column.date(),
    httpReferer: column.text({ optional: true }),
    countryCode: column.text({ optional: true }),
    visitorOS: column.text({ optional: true }),
    visitorDeviceType: column.text({ optional: true }),
    visitorBrowser: column.text({ optional: true }),
  },
});

const VisitingCountry = defineTable({
  columns: {
    siteId: column.number({ references: () => Site.columns.id }),
    countryCode: column.text(),
  },
});

// https://astro.build/db/config
export default defineDb({
  tables: {
    User,
    Site,
    Hit,
    VisitingCountry,
  },
});
