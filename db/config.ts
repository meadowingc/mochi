import { column, defineDb, defineTable } from "astro:db";

const User = defineTable({
  columns: {
    id: column.number({ primaryKey: true }),
    website: column.text(),
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
    httpReferer: column.text(),
    visitorIpHash: column.text(),
    visidorUserAgentHash: column.text(),
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
