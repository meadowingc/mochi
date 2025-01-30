import { db, Hit, Site, User } from "astro:db";

export default async function () {
  await db.insert(User).values([
    {
      id: 1,
      name: "Meadow",
      email: "meadowingc@proton.me",
      createdAt: new Date(),
    },
  ]);

  await db.insert(Site).values([
    {
      id: 1,
      userId: 1,
      url: "https://meadow.cafe",
      createdAt: new Date(),
    },
  ]);

  const hits: {
    siteId: number;
    path: string;
    date: Date;
  }[] = [];
  const paths = ["/", "/about", "/contact", "/products", "/blog"];
  const now = Date.now();

  for (let i = 0; i < 1000; i++) {
    // Generate 1000 random visits
    hits.push({
      siteId: 1,
      path: paths[Math.floor(Math.random() * paths.length)],
      date: new Date(now - Math.floor(Math.random() * 7 * 24 * 60 * 60 * 1000)), // Random date within the last 7 days
    });
  }

  await db.insert(Hit).values(hits);
}
