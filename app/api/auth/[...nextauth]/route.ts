import NextAuth, { AuthOptions } from "next-auth";
import { PrismaClient } from "@prisma/client";
import CredentialsProvider from "next-auth/providers/credentials";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

const prisma = new PrismaClient();

export const authOptions: AuthOptions =({
    providers: [
        CredentialsProvider({
            name: "Credentials",
            credentials: {
                username: { label: "Username", type: "text" },
                email: { label: "Email", type: "email" },
                password: { label: "Password", type: "password" },
            },
            authorize: async (credentials) => {
                if (!credentials) {
                    return null;
                }

                const { username, email, password } = credentials;

                const user = await prisma.profile.findFirst({
                    where: {
                        email,
                    },
                });

                if (!user) throw new Error("No user found");

                const userPassword = user.passwordHash;

                const isPasswordCorrect = await bcrypt.compare(password, userPassword);

                if (!isPasswordCorrect) throw new Error("Incorrect password");

                return user;
            },
        }),
    ],
    secret: process.env.NEXTAUTH_SECRET,
    session: {
        strategy: "jwt",
        maxAge: 60 * 60 * 24 * 30,
        updateAge: 60 * 60 * 24,
    },
    callbacks: {
        async jwt({ token, user }) {
            user && (token.user = user);
            return token;
        },
        async session({ session, token }) {
            session.user = token.user as any;
            return session;
        },
    },
    jwt: {
        async encode({ secret, token }) {
            if (!token) {
                throw new Error("No token to encode");
            }
            return jwt.sign(token, secret);
        },
        async decode({ secret, token }) {
            if (!token) {
                throw new Error("No token to decode");
            }
            const decodedToken = jwt.verify(token, secret);
            if (typeof decodedToken === "string") {
                return JSON.parse(decodedToken);
            } else {
                return decodedToken;
            }
        },
    },
});

const handler = NextAuth(authOptions)

export { handler as GET, handler as POST };