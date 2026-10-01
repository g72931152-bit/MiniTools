# CIPHER — Secure Capsule Platform

Клиентская криптографическая капсула с Live Access Control, Audit Log, expiration и one-time режимом. Проект рассчитан на GitHub + Cloudflare Workers Static Assets + Cloudflare D1.

## Архитектура

- `public/` — строгий интерфейс и Cipher Engine.
- `src/worker.js` — Cloudflare Worker API и контроль состояния.
- `migrations/0001_initial.sql` — схема D1.
- Plaintext не отправляется API.
- Основной AEAD: AES-256-GCM (нативный Web Crypto).
- Разделение ключей: HKDF-SHA-256.
- Access Code хранится на сервере только как SHA-256 hash.
- Secret Key остаётся на стороне клиента.

## Modes

`Standard`, `Timed` и `One-Time` автоматически допускают сессию после проверки Access Code; `Approval`, `Multi-Approval` и `Dead Drop` остаются на стадии owner policy. `Multi-Approval` и `Dead Drop` в этом релизе представлены как режимы данных/UI, но для полноценной многопользовательской политики требуется отдельный список approver credentials и условие release.

## Важное ограничение модели

Instant Revocation блокирует дальнейшие серверные операции и активные сессии, но не может физически удалить plaintext, который пользователь уже успел расшифровать или скопировать. Это фундаментальное свойство client-side decryption.

Также `localStorage` здесь используется как локальное хранилище демо-владельца. Для публичного production-варианта owner authentication, server-side session authentication и передача encrypted payload должны быть усилены отдельным identity-слоем.

## Cloudflare

1. Создайте D1 database.
2. Замените `database_id` в `wrangler.jsonc`.
3. Установите зависимости: `npm install`.
4. Примените миграцию локально: `npx wrangler d1 migrations apply cipher-platform --local`.
5. Примените миграцию в Cloudflare: `npx wrangler d1 migrations apply cipher-platform --remote`.
6. Запустите локально: `npm run dev`.
7. Деплой: `npm run deploy`.

Cloudflare Workers Static Assets позволяет разворачивать Worker и статические файлы одной операцией; D1 доступен на Workers Free для прототипов и экспериментов в пределах дневных лимитов. См. актуальную документацию Cloudflare.

## Проверка

`npm test` — криптографические round-trip/tamper tests и базовые API-тесты.
`npm run check` — синтаксическая проверка основных JS-файлов.
