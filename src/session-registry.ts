import WebSocket from "ws";

import { CliOptions } from "./cli";
import { MiniAppLaunchCoordinator } from "./launch-coordinator";
import {
    MiniAppSession,
    serializeSession,
} from "./session";

export class MiniAppSessionRegistry {
    private readonly sessions: Map<string, MiniAppSession>;

    constructor(
        private readonly launches: MiniAppLaunchCoordinator,
        sessions?: Map<string, MiniAppSession>,
    ) {
        this.sessions = sessions ?? new Map();
    }

    add(session: MiniAppSession) {
        this.sessions.set(session.id, session);
    }

    getExact(id: string) {
        return this.sessions.get(id);
    }

    remove(session: MiniAppSession) {
        for (const [id, currentSession] of this.sessions.entries()) {
            if (currentSession === session) {
                this.sessions.delete(id);
            }
        }
    }

    rekey(session: MiniAppSession, id: string) {
        this.remove(session);
        session.id = id;
        this.sessions.set(id, session);
    }

    values() {
        return Array.from(new Set(this.sessions.values()));
    }

    listByCreation() {
        return this.values().sort(
            (left, right) => left.createdAt - right.createdAt,
        );
    }

    isSocketOpen(session: MiniAppSession) {
        return session.debugSocket?.readyState === WebSocket.OPEN;
    }

    isDebuggable(session: MiniAppSession) {
        return (
            session.state === "ready" &&
            this.isSocketOpen(session) &&
            session.appService !== undefined &&
            !this.launches.isSessionQuarantined(session)
        );
    }

    listDebuggable() {
        return this.values()
            .filter((session) => this.isDebuggable(session))
            .sort((left, right) => left.createdAt - right.createdAt);
    }

    find(id: string) {
        return this.values()
            .filter(
                (session) =>
                    session.id === id ||
                    session.requestedAppId === id ||
                    session.resolvedAppId === id,
            )
            .sort(
                (left, right) =>
                    this.getScore(right) - this.getScore(left) ||
                    right.updatedAt - left.updatedAt,
            )[0];
    }

    getReady(appid: string) {
        const session = this.find(appid);
        return session && this.isDebuggable(session) ? session : undefined;
    }

    serializeAll(options: CliOptions) {
        return this.listByCreation().map((session) => {
            const serialized = serializeSession(options, session);
            const quarantined = this.launches.isSessionQuarantined(session);
            return {
                ...serialized,
                quarantined,
                targetUrl: quarantined ? null : serialized.targetUrl,
            };
        });
    }

    private getScore(session: MiniAppSession) {
        if (this.launches.isSessionQuarantined(session)) {
            return 0;
        }
        if (this.isDebuggable(session)) {
            return 4;
        }
        if (session.state === "bootstrapping" && this.isSocketOpen(session)) {
            return 3;
        }
        if (session.state === "closing" && this.isSocketOpen(session)) {
            return 2;
        }
        return 1;
    }
}
