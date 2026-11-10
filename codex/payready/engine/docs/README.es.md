<div align="center">

**El agente que elige e implementa el método de pago correcto para tu app — desde tu terminal, con Claude Code.**

[![Claude Code Plugin](https://img.shields.io/badge/Claude_Code-Plugin-E3754C?style=flat-square)](https://docs.claude.com/en/docs/claude-code/plugins)
[![License: MIT](https://img.shields.io/badge/License-MIT-000?style=flat-square)](../LICENSE)
[![CI](https://github.com/Hainrixz/agente-pagokit/actions/workflows/test.yml/badge.svg)](https://github.com/Hainrixz/agente-pagokit/actions/workflows/test.yml)

[`tododeia.com`](https://tododeia.com) · [`@soyenriquerocha`](https://instagram.com/soyenriquerocha) · `enrique@tododeia.com`

🇬🇧 **[Read in English](../README.md)** · 📖 **[About](../ABOUT.md)** · 🗺️ **[Cobertura](./COVERAGE.md)**

</div>

---

## Por qué existe<span style="color:#E3754C">.</span>

Todas las guías plantean la integración de pagos como un problema de *elección*: treinta
pasarelas, elige una. Elegir toma una tarde. Lo que toma semanas —y lo que falla en silencio en
producción— es todo lo que viene después:

- Un webhook que verifica la firma pero nunca revisa el timestamp: un evento capturado se puede reproducir para siempre.
- Un webhook verificado con la API key en vez del secreto de firma. Falla en todos los eventos, y el dev se va a depurar el algoritmo de hash.
- `amount * 100` con un cliente japonés. El yen no tiene unidad menor, así que eso es un **cobro 100× mayor**.
- Un endpoint de refund en una integración de Pix, donde reembolsar el cargo no es una operación que exista.
- Un handler de `payment_intent.succeeded` que da acceso, en una URL a la que cualquiera puede hacer POST.

Ninguno de estos lanza un error. Casi todos pasan code review. **PagoKit existe para que sean
difíciles de escribir.**

Analiza tu proyecto, te hace tres preguntas y genera una integración vertical completa:
frontend, endpoint de checkout, webhook autenticado, migración de base de datos, portal de
cliente, ruta de reembolso, mapeo de errores, checklist de producción y registro de auditoría.

**Todo corre local.** Sin cuenta, sin API key, sin telemetría. Las únicas llamadas de red son
las que tu código generado le hace a tu propio proveedor.

---

## Tres motores deterministas<span style="color:#E3754C">.</span>

Un LLM al que le pides código de pagos produce algo *plausible*. Y plausible es justamente el
modo de falla que importa acá. Así que las partes que tienen que estar bien no quedan en manos
del modelo: son programas normales, con tests.

| | Qué hace | Por qué no es trabajo del modelo |
|---|---|---|
| **Validadores** | Checks de Node en hooks `PreToolUse` / `PostToolUse` que **bloquean** una escritura insegura | El modelo no puede discutir con un exit code distinto de cero |
| **Advisor** | `scripts/advise.js` — una función pura de situación a ranking de proveedores | Misma entrada, misma respuesta, y cada rechazo trae su motivo. "¿Por qué no X?" tiene respuesta exacta |
| **Firmador** | `scripts/sign-event.js` — genera un evento **firmado válido** para cualquier proveedor | Probar un handler significa: evento válido aceptado, uno falsificado rechazado, uno reproducido rechazado |

<img src="https://raw.githubusercontent.com/Hainrixz/agente-pagokit/d3720d9fd292cc2cfffbd5b6f6fce5f45ede97fa/assets/architecture.svg" alt="Arquitectura de PagoKit" width="100%" />

---

## Lo que conoce<span style="color:#E3754C">.</span>

<!-- pagokit:stats:start -->
**42 proveedores** · **136 métodos de pago** · **74 países** (71 con proveedor local) · **106 monedas** con su exponente ISO 4217 · **6 familias de verificación de webhook** en uso.
<!-- pagokit:stats:end -->

<!-- pagokit:providers:start -->
### Lo que PagoKit escribe por ti

| Proveedor | Nivel | Rol | Cobertura de compradores | Suscripciones | MoR | Alta |
|---|---|---|---|---|---|---|
| **Lemon Squeezy** | build completo | mor | Global | ✓ | ✓ | application_review |
| **Mercado Pago** | build completo | psp | AR · BR · CL · CO · MX · PE · UY | ✓ | — | self_serve |
| **Stripe** | build completo | psp | US · CA · UK · EU · MX · BR · SG · AU · … | ✓ | — | self_serve |
| **Wompi** | build completo | acquirer | CO | — | — | application_review |

### Lo que PagoKit conoce y recomienda, pero no escribe

Otros 38 proveedores con datos verificados: el advisor los compara, calcula sus comisiones y explica sus condiciones — y te dice claramente que el código lo escribes tú. Suben a nivel `build` cuando su esquema de firma queda verificado y transcrito.

- **Ola 1** — Asaas · Bold.co · Conekta · Kushki · Paddle (Paddle Billing) · Polar
- **Ola 2** — Culqi · Flow.cl · Pagar.me · Transbank Webpay Plus · dLocal Go
- **Ola 3** — Fintoc · Mobbex · Placetopay (Evertec) · Recurrente · ePayco
- **Ola 4** — Adyen · GoCardless · Mollie · Redsys (TPV Virtual) · Revolut Merchant (Revolut Business)
- **Ola 5** — Airwallex · Antom (Ant International — Alipay+ / Alipay / WeChat Pay acquiring) · Midtrans (GoTo Financial) · PayMongo · Razorpay · Xendit
- **Ola 6** — Flutterwave · Paymob · Paystack · Safaricom M-Pesa (Daraja API) · Tap Payments · Yoco
- **Ola 7** — Authorize.Net (Visa Acceptance) · Hyperswitch (Juspay) · Lago · RevenueCat · Square
<!-- pagokit:providers:end -->

**Métodos de pago**, porque fuera de los mercados maduros en tarjeta la pregunta correcta es
qué *rail* necesitas, no qué pasarela:

<!-- pagokit:methods:start -->
| Categoría | Métodos | Ejemplos |
|---|---|---|
| Tarjetas | 8 | Bancontact · Credit/Debit Card · mada · Meeza · OmanNet |
| Wallets | 43 | Airtel Money · Alipay · AlipayHK · Alipay+ · Apple Pay |
| Transferencia bancaria | 31 | ACH Credit · Botón Bancolombia · Bancolombia Transfer · BenefitPay · Bre-B |
| QR / instantáneo | 11 | Bizum · CoDi · DuitNow · NQR (NIBSS QR) · PayNow |
| Vouchers en efectivo | 14 | Alfamart / Indomaret (cash over counter) · Baloto · Boleto Bancário · Efecty · Fawry |
| Débito directo | 8 | ACH Direct Debit · Bacs Direct Debit · BECS Direct Debit (Australia) · PAC (Chile direct debit) · PayTo |
| Dinero móvil | 2 | M-Pesa · MTN MoMo |
| BNPL | 11 | Afterpay / Clearpay · Akulaku PayLater · BillEase · Billie (B2B invoice / BNPL) · EMI / Cardless EMI (India) |
| Cripto | 2 | USDC Stablecoin · USDT Stablecoin |
| Open banking | 1 | Pay by Bank (open banking) |
| Presencial | 1 | Card present (terminal) |
| Beneficios (EBT/HSA) | 2 | SNAP EBT · HSA / FSA card |
| Facturación de tienda | 2 | Apple In-App Purchase · Google Play Billing |
<!-- pagokit:methods:end -->

Matriz completa país × proveedor: [`docs/COVERAGE.md`](./COVERAGE.md).

---

## Qué te va a construir y qué no<span style="color:#E3754C">.</span>

Un catálogo amplio solo sirve si es honesto sobre sus propios límites. Cada proveedor lleva un
nivel de integración, y el advisor **lo declara siempre**:

| Nivel | Qué pasa |
|---|---|
| **build** | PagoKit escribe la integración completa e idiomática. |
| **generic** | PagoKit escribe un scaffold funcional desde la familia de verificación del proveedor, y te dice que es un scaffold. |
| **advise** | PagoKit te da la recomendación, el cálculo de comisiones y un checklist — y dice claramente que el código lo escribes tú. |

Lo que sostiene eso es una regla que impone el build:

> Si el esquema de webhook de un proveedor no está verificado contra su propia documentación
> (`evidence.confidence != "high"`), el generador **no emite verificador de firma**. Emite
> re-fetch, dedup por id de evento y un TODO explícito.

Un verificador construido sobre un esquema sin verificar es peor que no tener ninguno: parece
correcto y acepta eventos falsificados.

---

## Cómo funciona<span style="color:#E3754C">.</span>

| Paso | Qué pasa |
|---|---|
| **1. SCAN** | Lee `package.json`, archivos de rutas, schema de DB. Detecta stack, ORM, deploy, idioma y casos de uso como marketplace o IAP móvil. |
| **2. ASK** | Tres preguntas, tope de cinco. País y compradores · cobro único o recurrente · qué rails locales necesitas. |
| **3. MATCH** | Corre el motor de ranking. Filtros duros primero — incluyendo *si siquiera puedes abrir cuenta ahí* y *si alcanzas a tener llaves a tiempo*. Los mercados sancionados se rechazan, no se rankean. |
| **4. BUILD** | El subagente `integration-specialist` escribe los archivos, con los validadores vigilando cada escritura. |

---

## Instalación<span style="color:#E3754C">.</span>

```bash
git clone https://github.com/Hainrixz/agente-pagokit ~/agente-pagokit
cd ~/tu-proyecto
claude --plugin-dir ~/agente-pagokit
```

Después ejecuta `/pagokit:start`.

> Requiere **Node.js ≥ 18** y **Claude Code 2.x**.

---

## Seguridad determinista<span style="color:#E3754C">.</span>

Las reglas de seguridad no son consejos en un markdown que el modelo puede o no seguir. Son
procesos de Node conectados a los hooks de Claude Code. Una escritura que rompe una regla se
**bloquea**.

| Bloquea | Porque |
|---|---|
| Un webhook sin verificación de firma | Cualquiera que sepa la URL puede fabricar un evento `succeeded` |
| `request.json()` antes de verificar | El HMAC cubre los bytes exactos; parsear primero lo rompe de forma permanente y silenciosa |
| `Math.random()` o `Date.now()` como idempotency key | Claves adivinables colisionan entre tenants y los reintentos duplican cobros |
| Una llave viva en el código | Historial de git, screenshots, trazas de Sentry |
| `.env` escrito antes de que `.gitignore` lo cubra | La fuga de credenciales más común que existe |
| `amount * 100` en una moneda de cero decimales | Un cobro 100× mayor que no lanza ningún error |
| `===` sobre una firma | Un oráculo de temporización — y en esquemas de secreto compartido *es* todo el control de seguridad |
| Datos de tarjeta pasando por tu servidor | Te mueve de PCI SAQ A a SAQ D, un proyecto de seis cifras |
| Un refund sobre un rail irreversible | En Pix o SPEI, "reembolsar el cargo" no es una operación |
| Un webhook que sobrescribiría uno existente | Pisar el endpoint de Clerk o Inngest de alguien |

Cuando la herramienta se equivoca y tú tienes razón:

```ts
// pagokit-ignore: webhook-has-signature -- verificador propio en lib/auth/payments.ts
```

Cada bypass queda en `.pagokit/audit.log`, así que es una decisión registrada y no un hueco
silencioso.

Reglas completas con sus niveles de enforcement: [`SECURITY_RULES.md`](../skills/payment-advisor/SECURITY_RULES.md).

---

## Comandos<span style="color:#E3754C">.</span>

| Comando | Qué hace |
|---|---|
| `/pagokit:start` | El wizard: analiza, pregunta, recomienda, implementa. |
| `/pagokit:test` | Manda un evento válido, uno **falsificado** y uno **reproducido** a tu handler local. Funciona con cualquier proveedor cuyo esquema sea firmable — no solo con el que tiene CLI. |
| `/pagokit:doctor` | Auditoría de solo lectura de una integración existente: credenciales, modo de las llaves, verificación de firma, eventos ruteados, schema, protección de replay. |

---

## Lo que se genera<span style="color:#E3754C">.</span>

Para un proyecto Next.js App Router + Prisma:

```
app/api/checkout/route.ts        Precio consultado en el servidor · idempotency UUID · unidades menores correctas
app/api/webhook/<provider>/      Raw body · firma · ventana de replay · dedup por event id · ack rápido
app/api/portal/route.ts          Autoservicio del cliente (suscripciones)
app/api/refund/route.ts          Con verificación de autorización — o la ruta de payout en rails irreversibles
components/CheckoutButton.tsx    Hosted, embedded o widget, según el proveedor
lib/payments/<provider>.ts       Init del SDK · versión de API fijada
lib/payments/errors.ts           Taxonomía de errores cross-provider · ES/EN
prisma/schema.prisma             payments · subscriptions · customers · idempotency_keys
                                 · webhook_events_processed
payment-page-scripts.json        Inventario de scripts autorizados (PCI DSS 4.0.1 §6.4.3)
.env.example                     Solo valores de test
PAGOKIT_INTEGRATION.md           Registro de auditoría · eventos ruteados · qué queda pendiente
PAGOKIT_PRODUCTION_CHECKLIST.md  Pasos para salir a producción
PAGOKIT_TAX_TODO.md              Solo donde el país exige facturación electrónica
```

Con otros stacks la estructura se adapta; las garantías no cambian.

---

## Rails locales que conoce<span style="color:#E3754C">.</span>

Fuera de los mercados maduros en tarjeta, el rail importa más que la pasarela. El advisor
recomienda el rail antes que el proveedor:

<!-- pagokit:rails:start -->
| País | Rail instantáneo dominante |
|---|---|
| `AR` | Transferencias 3.0 |
| `AU` | PayTo |
| `BR` | Pix |
| `CO` | PSE (Pagos Seguros en Línea) |
| `CR` | Sinpe Movil |
| `DE` | SEPA Instant Credit Transfer |
| `ES` | Bizum |
| `FR` | SEPA Instant Credit Transfer |
| `HK` | FPS |
| `IN` | UPI |
| `IT` | SEPA Instant Credit Transfer |
| `KE` | M-Pesa |
| `MX` | SPEI |
| `NG` | NIBSS Instant Payment |
| `NL` | SEPA Instant Credit Transfer |
| `PE` | Yape |
| `PT` | MB WAY |
| `SG` | PayNow |
| `UK` | Faster Payments |
| `US` | RTP (Real-Time Payments) |
| `ZA` | PayShap |
<!-- pagokit:rails:end -->

---

## Roadmap<span style="color:#E3754C">.</span>

Las olas están ordenadas por *calidad de evidencia × rails que desbloquean ÷ costo de
plantillas*, no por tamaño de mercado. Un proveedor cuyo esquema de firma no se puede verificar
no es un ítem de ola: es un ticket de investigación.

| Ola | Foco | Qué desbloquea |
|---|---|---|
| **0** ✅ | Fundación | Specs de webhook tipados, motor de recomendación, firmador de eventos, tabla de exponentes de moneda, validadores manejados por datos |
| **1** | Continuidad MoR + familias de verificación LATAM | Paddle · Polar · Conekta · Bold · Asaas · Kushki → Ecuador, y las familias RSA / body-transform / secreto compartido que reutilizan una docena de proveedores después |
| **2** | "El payload no es autoritativo" | Transbank · Flow · dLocal Go · Culqi · Pagar.me → Chile y Perú de verdad, más los modelos `return_url_commit` y `ping_then_poll` |
| **3** | Cola larga LATAM | Fintoc · Recurrente · ePayco · Mobbex · Placetopay → Centroamérica tiene una respuesta real |
| **4** | Europa self-serve | Mollie · Revolut · Redsys · GoCardless · Adyen → iDEAL, Bancontact, BLIK, Bizum, mandatos SEPA y Bacs |
| **5** | Asia | Razorpay · Xendit · Midtrans · PayMongo · Airwallex · Antom → UPI, QRIS, PayNow, PromptPay, Alipay+ |
| **6** | África y MENA | Paystack · Yoco · Flutterwave · Paymob · Tap · M-Pesa → mada, KNET, M-Pesa, MoMo, PayShap |
| **7** | Categorías nuevas | Square · Authorize.Net · RevenueCat · Lago · Hyperswitch · Forage → presencial, verticales de alto riesgo, IAP móvil, facturación medida, orquestación, SNAP EBT |

---

## Desarrollo<span style="color:#E3754C">.</span>

```bash
npm install
npm run verify            # todo: schemas, invariantes de integridad, todas las suites
npm run generate:all      # regenera todos los archivos derivados
./scripts/dev-link.sh /ruta/al/proyecto-de-prueba
```

| Puerta | Qué atrapa |
|---|---|
| `validate:data` | Violaciones de schema, ids duplicados, referencias colgantes, mentiras de cobertura, y los dos invariantes: ninguna afirmación de LLM marcada como alta confianza, ningún proveedor build sin esquema verificado |
| `test:validators` | Fixtures de validadores — la violación, el código correcto, el caso límite que **no** debe dar falso positivo, y el bypass |
| `test:advisor` | Cada recomendación incorrecta que PagoKit podría dar, congelada como fixture |
| `test:signatures` | Por proveedor: firmar → verificar → y rechazar body alterado, secreto incorrecto, header faltante y replay |
| `check:*` | Deriva en cualquier archivo generado — cobertura, firmas, tabla del doctor, tablas del README, catálogo |

Nada generado se edita a mano. Ver [`CONTRIBUTING.md`](../CONTRIBUTING.md).

### Por qué la cantidad de archivos no explota

<img src="https://raw.githubusercontent.com/Hainrixz/agente-pagokit/d3720d9fd292cc2cfffbd5b6f6fce5f45ede97fa/assets/verification-families.svg" alt="Los fragmentos por familia de verificación son aditivos, no multiplicativos" width="100%" />

Los proveedores difieren en pocas dimensiones, y esas dimensiones se repiten. Una plantilla por
proveedor hace que la cuenta sea `proveedores × stacks × modos de cobro`. Un fragmento por
**familia de capacidad** la hace aditiva — y agregar el proveedor 41 cuesta una entrada de JSON
más un override chico, no dos docenas de documentos.

---

## Seguridad<span style="color:#E3754C">.</span>

¿Encontraste una vulnerabilidad? **No abras un issue público.** Escribe a `security@tododeia.com`
o usa [GitHub Security Advisories](https://github.com/Hainrixz/agente-pagokit/security/advisories/new).
Respuesta en 48 horas. Política completa: [`SECURITY.md`](../SECURITY.md).

---

## Autor<span style="color:#E3754C">.</span>

**Enrique Rocha** · [`tododeia.com`](https://tododeia.com) · [`@soyenriquerocha`](https://instagram.com/soyenriquerocha) · `enrique@tododeia.com`

Consultoría de IA · agentes · automatizaciones · sprints en Miami.

Si te ahorró días de trabajo, mándame un screenshot. Si rompió algo, abre un issue.

---

[MIT](../LICENSE) · 2026 Enrique Rocha · `tododeia.`
