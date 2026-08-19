const express = require('express');
const session = require('express-session');
const path = require('path');
const crypto = require('crypto');

const app = express();

const PORT = Number(process.env.PORT || 3000);

const SITE_URL =
    (process.env.SITE_URL ||
    `http://localhost:${PORT}`).replace(/\/$/, '');

const STEAM_API_KEY =
    process.env.STEAM_API_KEY || '';

const SESSION_SECRET =
    process.env.SESSION_SECRET || '';

const SERVER_SECRET =
    process.env.SERVER_SECRET || '';

const SERVER_ID =
    process.env.SERVER_ID || 'site19';

const ADMIN_STEAM_IDS =
    new Set(
        (process.env.ADMIN_STEAM_IDS || '')
            .split(',')
            .map(v => v.trim())
            .filter(Boolean)
    );


/*
==================================================
 CONFIGURATION
==================================================
*/

if (
    !STEAM_API_KEY ||
    !SESSION_SECRET ||
    !SERVER_SECRET ||
    ADMIN_STEAM_IDS.size === 0
) {
    console.warn(
        '[CONFIG] Configuration incomplète.'
    );
}


/*
==================================================
 EXPRESS
==================================================
*/

app.set('trust proxy', 1);

app.use(
    express.json()
);

app.use(
    express.urlencoded({
        extended: false
    })
);


/*
==================================================
 SESSION
==================================================
*/

app.use(
    session({
        name: 'return.sid',

        secret:
            SESSION_SECRET ||
            crypto.randomBytes(32).toString('hex'),

        resave: false,

        saveUninitialized: false,

        cookie: {
            httpOnly: true,
            sameSite: 'lax',
            secure:
                process.env.NODE_ENV === 'production',
            maxAge:
                1000 * 60 * 60 * 24 * 7
        }
    })
);


/*
==================================================
 SERVEURS GARRY'S MOD
==================================================
*/

const servers = new Map();


function getServerState() {

    const state =
        servers.get(SERVER_ID);

    if (!state) {
        return null;
    }

    /*
    Heartbeat toutes les 10 secondes.
    Si aucun heartbeat depuis 30 secondes,
    le serveur est considéré hors ligne.
    */

    if (
        Date.now() -
        state.lastHeartbeat >
        30000
    ) {
        return null;
    }

    return state;
}


/*
==================================================
 STEAM
==================================================
*/

function parseSteamIdFromClaimedId(
    claimedId
) {

    const match =
        /^https?:\/\/steamcommunity\.com\/openid\/id\/(\d+)$/
            .exec(
                claimedId || ''
            );

    return match
        ? match[1]
        : null;
}


async function getSteamProfile(
    steamId
) {

    if (!STEAM_API_KEY) {

        throw new Error(
            'STEAM_API_KEY manquante'
        );
    }

    const url =
        new URL(
            'https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/'
        );

    url.searchParams.set(
        'key',
        STEAM_API_KEY
    );

    url.searchParams.set(
        'steamids',
        steamId
    );

    const response =
        await fetch(url);

    if (!response.ok) {

        throw new Error(
            `Steam API HTTP ${response.status}`
        );
    }

    const data =
        await response.json();

    const player =
        data?.response?.players?.[0];

    if (
        !player ||
        player.steamid !== steamId
    ) {
        return null;
    }

    return player;
}


/*
==================================================
 SÉCURITÉ
==================================================
*/

function safeEqual(
    a,
    b
) {

    const aa =
        Buffer.from(
            String(a || '')
        );

    const bb =
        Buffer.from(
            String(b || '')
        );

    return (
        aa.length === bb.length &&
        crypto.timingSafeEqual(
            aa,
            bb
        )
    );
}


function isAdmin(
    steamId
) {

    return (
        !!steamId &&
        ADMIN_STEAM_IDS.has(
            String(steamId)
        )
    );
}


function isOnConfiguredServer(
    steamId
) {

    const state =
        getServerState();

    if (!state) {
        return false;
    }

    return state.players.has(
        String(steamId)
    );
}


/*
==================================================
 PROTECTION ADMIN
==================================================
*/

async function requireAdmin(
    req,
    res,
    next
) {

    if (!req.session.steamId) {

        return res.status(401).json({
            ok: false,
            code:
                'STEAM_LOGIN_REQUIRED',
            message:
                'Connexion Steam requise.'
        });
    }


    if (
        !isAdmin(
            req.session.steamId
        )
    ) {

        return res.status(403).json({
            ok: false,
            code:
                'NOT_ADMIN',
            message:
                'Ce compte Steam n’est pas administrateur.'
        });
    }


    if (
        !isOnConfiguredServer(
            req.session.steamId
        )
    ) {

        return res.status(403).json({
            ok: false,
            code:
                'NOT_ON_SERVER',
            message:
                'Vous devez être connecté au serveur Return SCP-RP.'
        });
    }


    next();
}


/*
==================================================
 CONNEXION STEAM
==================================================
*/

app.get(
    '/auth/steam',
    (req, res) => {

        const returnTo =
            `${SITE_URL}/auth/steam/callback`;

        const realm =
            `${SITE_URL}/`;

        const params =
            new URLSearchParams({

                'openid.ns':
                    'http://specs.openid.net/auth/2.0',

                'openid.mode':
                    'checkid_setup',

                'openid.return_to':
                    returnTo,

                'openid.realm':
                    realm,

                'openid.identity':
                    'http://specs.openid.net/auth/2.0/identifier',

                'openid.claimed_id':
                    'http://specs.openid.net/auth/2.0/identifier'
            });


        res.redirect(
            `https://steamcommunity.com/openid/login?${params.toString()}`
        );
    }
);


/*
==================================================
 CALLBACK STEAM
==================================================
*/

app.get(
    '/auth/steam/callback',
    async (req, res) => {

        try {

            const claimedId =
                String(
                    req.query[
                        'openid.claimed_id'
                    ] || ''
                );

            const mode =
                String(
                    req.query[
                        'openid.mode'
                    ] || ''
                );


            if (
                mode !== 'id_res' ||
                !claimedId
            ) {

                return res.redirect(
                    '/?steam_error=invalid_response'
                );
            }


            /*
            Vérification auprès de Steam
            */

            const verifyParams =
                new URLSearchParams();


            for (
                const [key, value]
                of Object.entries(req.query)
            ) {

                if (
                    key === 'openid.mode'
                ) {
                    continue;
                }

                verifyParams.set(
                    key,
                    Array.isArray(value)
                        ? value[0]
                        : String(value)
                );
            }


            verifyParams.set(
                'openid.mode',
                'check_authentication'
            );


            const verifyResponse =
                await fetch(
                    'https://steamcommunity.com/openid/login',
                    {
                        method: 'POST',

                        headers: {
                            'Content-Type':
                                'application/x-www-form-urlencoded'
                        },

                        body:
                            verifyParams.toString()
                    }
                );


            const verifyText =
                await verifyResponse.text();


            if (
                !verifyResponse.ok ||
                !/^is_valid\s*:\s*true\s*$/mi
                    .test(
                        verifyText
                    )
            ) {

                return res.redirect(
                    '/?steam_error=verification_failed'
                );
            }


            /*
            SteamID64
            */

            const steamId =
                parseSteamIdFromClaimedId(
                    claimedId
                );


            if (!steamId) {

                return res.redirect(
                    '/?steam_error=invalid_steamid'
                );
            }


            /*
            Vérification Steam Web API
            */

            const profile =
                await getSteamProfile(
                    steamId
                );


            if (!profile) {

                return res.redirect(
                    '/?steam_error=steam_api_failed'
                );
            }


            /*
            Création de session
            */

            req.session.steamId =
                steamId;

            req.session.profile = {

                steamid:
                    profile.steamid,

                personaname:
                    profile.personaname,

                avatar:
                    profile.avatarfull ||
                    profile.avatarmedium ||
                    profile.avatar,

                profileurl:
                    profile.profileurl
            };


            res.redirect('/');

        } catch (error) {

            console.error(
                '[STEAM LOGIN]',
                error
            );

            res.redirect(
                '/?steam_error=server_error'
            );
        }
    }
);


/*
==================================================
 DÉCONNEXION
==================================================
*/

app.post(
    '/auth/logout',
    (req, res) => {

        req.session.destroy(
            () => {

                res.clearCookie(
                    'return.sid'
                );

                res.json({
                    ok: true
                });
            }
        );
    }
);


/*
==================================================
 API UTILISATEUR
==================================================
*/

app.get(
    '/api/me',
    async (req, res) => {

        if (
            !req.session.steamId
        ) {

            return res.json({
                loggedIn: false
            });
        }


        try {

            const profile =
                await getSteamProfile(
                    req.session.steamId
                );


            if (!profile) {

                throw new Error(
                    'Profil Steam introuvable'
                );
            }


            const admin =
                isAdmin(
                    req.session.steamId
                );


            const onServer =
                isOnConfiguredServer(
                    req.session.steamId
                );


            req.session.profile = {

                steamid:
                    profile.steamid,

                personaname:
                    profile.personaname,

                avatar:
                    profile.avatarfull ||
                    profile.avatarmedium ||
                    profile.avatar,

                profileurl:
                    profile.profileurl
            };


            res.json({

                loggedIn: true,

                profile:
                    req.session.profile,

                admin,

                onServer,

                adminPanelAllowed:
                    admin &&
                    onServer
            });

        } catch (error) {

            console.error(
                '[ME]',
                error
            );

            res.status(502).json({

                ok: false,

                code:
                    'STEAM_API_UNAVAILABLE'
            });
        }
    }
);


/*
==================================================
 VÉRIFICATION PANEL
==================================================
*/

app.get(
    '/api/admin/check',
    requireAdmin,
    async (req, res) => {

        try {

            const profile =
                await getSteamProfile(
                    req.session.steamId
                );


            if (!profile) {

                return res.status(403).json({

                    ok: false,

                    code:
                        'STEAM_PROFILE_INVALID'
                });
            }


            res.json({

                ok: true,

                steamId:
                    req.session.steamId,

                playerName:
                    profile.personaname,

                serverId:
                    SERVER_ID,

                verifiedBySteamApi:
                    true,

                connectedToServer:
                    true
            });

        } catch (error) {

            console.error(
                '[ADMIN CHECK]',
                error
            );

            res.status(502).json({

                ok: false,

                code:
                    'STEAM_API_UNAVAILABLE'
            });
        }
    }
);


/*
==================================================
 HEARTBEAT GARRY'S MOD
==================================================
*/

app.post(
    '/api/server/heartbeat',
    (req, res) => {

        const incomingSecret =
            req.get(
                'X-Server-Secret'
            );


        if (
            !safeEqual(
                incomingSecret,
                SERVER_SECRET
            )
        ) {

            return res.status(401).json({
                ok: false
            });
        }


        const serverId =
            String(
                req.body.server_id ||
                SERVER_ID
            );


        if (
            serverId !== SERVER_ID
        ) {

            return res.status(400).json({

                ok: false,

                message:
                    'Serveur inconnu.'
            });
        }


        let players = [];


        try {

            players =
                typeof req.body.players === 'string'
                    ? JSON.parse(
                        req.body.players
                    )
                    : req.body.players;

        } catch (_) {

            return res.status(400).json({

                ok: false,

                message:
                    'Liste de joueurs invalide.'
            });
        }


        if (
            !Array.isArray(players)
        ) {

            return res.status(400).json({

                ok: false,

                message:
                    'players doit être un tableau.'
            });
        }


        const normalized =
            new Set(
                players
                    .map(String)
                    .filter(
                        id =>
                            /^\d{17}$/.test(id)
                    )
            );


        servers.set(
            serverId,
            {

                lastHeartbeat:
                    Date.now(),

                players:
                    normalized
            }
        );


        res.json({

            ok: true,

            playerCount:
                normalized.size
        });
    }
);


/*
==================================================
 PROTECTION ADMIN.HTML
==================================================
*/

app.get(
    '/admin.html',
    (req, res) => {

        if (
            !req.session.steamId
        ) {

            return res.redirect(
                '/?admin_error=steam_login_required'
            );
        }


        if (
            !isAdmin(
                req.session.steamId
            )
        ) {

            return res.redirect(
                '/?admin_error=not_admin'
            );
        }


        if (
            !isOnConfiguredServer(
                req.session.steamId
            )
        ) {

            return res.redirect(
                '/?admin_error=not_on_server'
            );
        }


        res.sendFile(
            path.join(
                __dirname,
                'admin.html'
            )
        );
    }
);


/*
==================================================
 HEALTH
==================================================
*/

app.get(
    '/health',
    (req, res) => {

        const state =
            getServerState();

        res.json({

            ok: true,

            steamApiConfigured:
                !!STEAM_API_KEY,

            serverOnline:
                !!state
        });
    }
);


/*
==================================================
 INDEX
==================================================
*/

app.get(
    '/',
    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                'index.html'
            )
        );
    }
);


/*
==================================================
 START
==================================================
*/

app.listen(
    PORT,
    () => {

        console.log(
            `Return Community lancé sur ${SITE_URL}`
        );
    }
);
