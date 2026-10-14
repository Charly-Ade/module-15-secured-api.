import app from "./app";
import { env } from "./config/env";
import { seedAdmin } from "./services/seedAdmin";

seedAdmin()
  .then(() => {
    app.listen(env.PORT, () => {
      console.log(`Server running on http://localhost:${env.PORT}`);
    });
  })
  .catch((error: unknown) => {
    console.error("Failed to start:", error);
    process.exit(1);
  });
