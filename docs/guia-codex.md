---
title: Guía de PayReady para Codex
---

# Guía de PayReady para Codex

Imagina que vendes un curso desde México. Ya tienes una página donde lo describes y quieres agregar un botón para cobrar. Aún te falta decidir qué pasarela usar, cómo registrar el pedido y qué señal debe recibir tu sistema antes de dar acceso. PayReady te acompaña en esas tres decisiones.

Una **pasarela** es el servicio que procesa el cobro. El **checkout** es la pantalla donde paga tu cliente. Un **webhook** es un aviso que el proveedor envía a tu servidor cuando cambia el estado del pago. Que el comprador regrese a una pantalla de «gracias» solo confirma que llegó a esa página. Tu aplicación debe comprobar el estado real antes de entregar el producto.

## Antes de abrir PayReady

Ten a la mano la carpeta de tu proyecto, Node.js 18 o superior y el asistente de esta edición. Usa Git si vas a clonar el repositorio. Puedes empezar con un proyecto existente o desde una carpeta vacía. Para la primera conversación te bastan cuatro datos: qué vendes, desde dónde, a quién y cómo quieres cobrar. Las credenciales pueden esperar hasta que elijas proveedor y vayas a probar.

## Instala la skill y abre tu proyecto

Instala la carpeta completa de PayReady para conservar los scripts y el catálogo. En Windows PowerShell:

```powershell
$repo = Join-Path $env:USERPROFILE 'payready'
$skills = Join-Path $env:USERPROFILE '.agents/skills'
git clone https://github.com/Alanmezaoficial/payready.git $repo
if ($LASTEXITCODE -ne 0) { throw 'Revisa el clon antes de continuar.' }
New-Item -ItemType Directory -Force $skills | Out-Null
if (Test-Path (Join-Path $skills 'payready')) { throw 'Ya hay una copia de PayReady. Revisa su versión.' }
Copy-Item (Join-Path $repo 'codex/payready') -Destination $skills -Recurse -ErrorAction Stop
```

En macOS y Linux:

```sh
git clone https://github.com/Alanmezaoficial/payready.git ~/payready &&
mkdir -p ~/.agents/skills &&
test ! -e ~/.agents/skills/payready &&
cp -R ~/payready/codex/payready ~/.agents/skills/payready
```

Si tienes el ZIP de Codex, copia la carpeta extraída `payready` al mismo directorio de skills. Verifica que exista `~/.agents/skills/payready/SKILL.md` y que sus carpetas `engine` y `scripts` estén al mismo nivel. Abre una sesión nueva de Codex en tu proyecto y escribe:

```text
Usa $payready para analizar este proyecto y recomendarme cómo integrar pagos de prueba.
```

## Qué te preguntará y cómo responder

Al empezar, PayReady lee la estructura del proyecto para ubicar el frontend, el servidor, la base de datos y los cobros que ya existan. Te mostrará lo que detectó para que corrijas, por ejemplo, si encontró una carpeta de pruebas y la tomó por el servidor principal. Si empiezas desde una carpeta vacía, te pedirá contexto sobre lo que quieres vender.

### 1. ¿Desde dónde cobras y dónde están tus compradores?

Distingue el país de tu negocio del país de tus clientes. «Mi negocio está en México y mis compradores están en México y Estados Unidos» es más útil que «vendo por internet». Esta respuesta ayuda a descartar proveedores que no pueden abrirte una cuenta o no cubren las monedas y los mercados que necesitas.

### 2. ¿Pagará cada cliente una vez o habrá renovaciones?

Para un curso vendido por separado, di «un pago por compra». Para una membresía, indica si es mensual o anual y si el cliente debe poder cancelarla desde su cuenta. Si manejas ambos modelos, describe cada uno y decide cuál quieres probar primero. Una suscripción trae estados adicionales, como renovación fallida, cambio de plan y cancelación.

### 3. ¿Qué formas de pago deben estar disponibles?

Separa lo indispensable de lo deseable. Por ejemplo, «tarjeta y OXXO son indispensables, transferencia sería un extra». Si aceptas un método de pago diferido, como un vale para pagar en tienda, tu aplicación necesita mostrar **pendiente** hasta recibir una confirmación válida. Generar el vale por sí solo no completa el cobro.

PayReady puede pedir hasta dos aclaraciones cuando cambian la decisión. Por ejemplo, qué tipo de producto vendes, cuándo necesitas tener activa la cuenta o si buscas un proveedor que se encargue de ciertas obligaciones de la venta. Si ya diste el dato, puede usarlo en la recomendación.

## Cómo leer la recomendación

La respuesta debería decir qué pasarela encaja, qué requisito cubre, qué condiciones conviene confirmar y qué parte de la integración puede generar. Si muestra cuánto te quedaría de una venta, revisa el importe, la moneda, los supuestos y la fecha del dato. Compara las tarifas y los métodos contra la documentación oficial y la configuración de tu cuenta.

Para ubicarte, el paquete trae plantillas dedicadas para Stripe, Mercado Pago, Wompi y Lemon Squeezy. Los siguientes casos sirven para orientar la conversación, sin presuponer que la cuenta o el método estarán disponibles:

- **Stripe** es un candidato cuando necesitas checkout con tarjeta o un flujo de suscripción. Pide que revise el país de tu negocio, tu moneda y los medios locales que son obligatorios.
- **Mercado Pago** es un candidato cuando los medios locales de un mercado latinoamericano pesan en la decisión. Pide una evaluación para el país específico donde vas a operar.
- **Wompi** es un candidato para una operación centrada en Colombia. Si quieres cobrar con PSE o Nequi, solicita que compruebe el método y la modalidad en la cuenta.
- **Lemon Squeezy** es un candidato para vender productos digitales si te interesa que el proveedor actúe como vendedor frente al comprador. Verifica que admita tu producto, país de operación y formas de cobro.

El catálogo incluye más opciones. Una **plantilla dedicada** aporta piezas específicas para el proveedor y el stack. Una **base genérica** necesita contrastar el código con la documentación del proveedor. Cuando la cobertura es de **asesoría**, el resultado es una recomendación y una lista de pasos para una implementación manual. Pide que marque cuál aplica antes de autorizar cambios.

## Ejemplo de una primera sesión

Supón que el curso cuesta **499 MXN** y se compra una vez. Puedes responder con este mensaje cuando te pida contexto:

> Vendo un curso digital desde México a compradores de México. Cuesta 499 MXN y se paga una sola vez. Necesito tarjeta y quiero ofrecer OXXO si mi cuenta lo permite. Explícame qué pasarela propones y qué puede generar en este proyecto. Espera mi autorización antes de editar.

Si la recomendación encaja, el siguiente pedido puede ser:

> Prepara una integración de prueba para este curso. Usa el precio del catálogo en el servidor. Si el pago queda pendiente, muestra el estado y espera la confirmación del proveedor antes de habilitar el acceso. Muéstrame qué archivos cambiaste y cómo probarlo.

La decisión real depende del proyecto y de los métodos habilitados. Si OXXO es obligatorio para tu negocio, dilo antes de aceptar el proveedor.

## Qué puede cambiar en tu proyecto

Los nombres de carpetas varían entre frameworks. Next.js App Router y Express cuentan con adaptadores incluidos. Si ya tienes otro stack o modelo de datos, pide primero que identifique las piezas compatibles y las que tendrá que dejar como guía manual.

- **Pantalla de compra.** El botón inicia el checkout y puede llevar al cliente a la página del proveedor.
- **Servidor de pagos.** Una ruta crea la sesión con un importe calculado en el servidor. Otra recibe la notificación, verifica que sea auténtica y actualiza el pedido. Según el caso pueden añadirse un portal para el cliente o una ruta de reembolso protegida.
- **Base de datos.** Guarda el estado de la compra, los identificadores del proveedor y los eventos ya procesados. Para suscripciones puede guardar también el estado de la membresía. Revisa la migración si ya tienes datos.
- **Configuración y entrega.** El ejemplo de variables te indica qué valores configurar. El resumen de integración enumera rutas y archivos. La lista de salida a producción deja por escrito las verificaciones pendientes.

## Cómo comprobar tu primera venta

1. Usa una cuenta de pruebas del proveedor y una base de datos de desarrollo. Configura tus secretos en el entorno local y conserva solo marcadores en el archivo de ejemplo.
2. Abre el checkout como cliente y completa una compra de prueba. Comprueba que importe y moneda coincidan con lo que vendes. Prueba también un pago cancelado o rechazado.
3. Envía una notificación válida a tu aplicación. Comprueba que el pedido pase al estado correcto. Prueba además una firma alterada y verifica que no entregue acceso.
4. Repite el mismo evento y confirma que el sistema no entregue el producto dos veces. Si la firma incorpora una marca de tiempo, comprueba que también rechace avisos que quedaron fuera de la ventana permitida.
5. Si vendes con un método diferido, comprueba que el pedido permanezca pendiente hasta que el proveedor confirme. Si vendes por suscripción, prueba renovación, fallo de cobro y cancelación según el alcance de tu integración.

Cuando la firma no se pueda simular localmente, utiliza el entorno de pruebas del proveedor. Antes de cobrar en producción, revisa las variables, el webhook configurado y los resultados con quien vaya a operar la aplicación.

## Qué revisan las reglas de seguridad

- **Secretos.** Busca credenciales incrustadas en el código y revisa que los archivos de entorno estén excluidos del repositorio.
- **Autenticidad.** Comprueba si el webhook incluye los pasos esperados para validar su firma y conserva el cuerpo original cuando el proveedor lo requiere.
- **Operaciones repetidas.** Revisa cómo se identifican los intentos de cobro y cómo se reconocen los eventos que el proveedor vuelve a enviar.
- **Importes y datos sensibles.** Busca errores comunes con unidades de moneda, precios recibidos del navegador y registros con datos sensibles.

Los chequeos identifican patrones en el código. Verifica su comportamiento con pruebas y registra cualquier caso pendiente antes de habilitar el flujo.

## Qué pedirle a Codex después del diagnóstico

- «Usa PayReady para comparar estas dos pasarelas con mis métodos obligatorios».
- «Audita el checkout y el webhook actuales. Dame los hallazgos por archivo».
- «Ejecuta los validadores de PayReady sobre los archivos que cambiaron y enséñame qué casos de pago, firma y repetición comprobaste».
- «Prepara un plan para agregar otro proveedor o migrar las suscripciones activas».

Codex ejecuta los validadores de forma explícita durante la revisión. Si el chat abierto no encuentra la skill, comprueba la carpeta de instalación y vuelve a abrir Codex en el proyecto.
