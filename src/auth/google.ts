import passport from "passport";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";
import type { Profile } from "passport-google-oauth20";
import { env } from "../config/env";
import * as usersService from "../services/usersService";
import type { User } from "../types";

export const isGoogleConfigured = (): boolean =>
  Boolean(
    env.GOOGLE_CLIENT_ID &&
      env.GOOGLE_CLIENT_SECRET &&
      env.GOOGLE_CALLBACK_URL,
  );

type Outcome = { user: User } | { error: string };

export const findOrCreateGoogleUser = (profile: Profile): Outcome => {
  const googleId = profile.id;
  const email = profile.emails?.[0]?.value?.trim().toLowerCase();

  if (!googleId || !email) {
    return { error: "google_no_email" };
  }

  // Only accept an email explicitly verified by Google.
  if (profile._json?.email_verified !== true) {
    return { error: "google_email_unverified" };
  }

  const existingUser = usersService.findByGoogleId(googleId);

  if (existingUser) {
    return { user: existingUser };
  }

  const existingEmail = usersService.findByEmail(email);

  if (existingEmail) {
    return { error: "email_already_registered" };
  }

  const user = usersService.createUser({
    name: (profile.displayName || email.split("@")[0]).slice(0, 100),
    email,
    passwordHash: null,
    googleId,
    role: "user",
  });

  return { user };
};

export const configureGoogleStrategy = (): void => {
  passport.use(
    new GoogleStrategy(
      {
        clientID: env.GOOGLE_CLIENT_ID!,
        clientSecret: env.GOOGLE_CLIENT_SECRET!,
        callbackURL: env.GOOGLE_CALLBACK_URL!,
        ...(process.env.GOOGLE_TEST_BASE_URL
          ? {
              authorizationURL: `${process.env.GOOGLE_TEST_BASE_URL}/auth`,
              tokenURL: `${process.env.GOOGLE_TEST_BASE_URL}/token`,
              userProfileURL: `${process.env.GOOGLE_TEST_BASE_URL}/userinfo`,
            }
          : {}),
      },
      (_accessToken, _refreshToken, profile, done) => {
        try {
          const result = findOrCreateGoogleUser(profile);

          if ("error" in result) {
            return done(null, false, { message: result.error });
          }

          return done(null, result.user);
        } catch (error) {
          return done(error as Error);
        }
      },
    ),
  );
};