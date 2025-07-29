// Mostrar/ocultar el botón según el scroll con transición suave
document.addEventListener('DOMContentLoaded', function() {
  const btn = document.getElementById("goTopBtn");
  window.addEventListener('scroll', function() {
    if (document.body.scrollTop > 200 || document.documentElement.scrollTop > 200) {
      btn.classList.add("show");
    } else {
      btn.classList.remove("show");
    }
  });
  btn.onclick = function() {
    window.scrollTo({top: 0, behavior: 'smooth'});
  };
});

function copiarComando(comando) {
  // Crea un elemento temporal para copiar el texto
  navigator.clipboard.writeText(comando).then(function() {
    // Busca todos los mensajes de copiado y los oculta
    document.querySelectorAll('[id^="copiado-"]').forEach(function(el) {
      el.classList.add('d-none');
    });
    // Busca el colapso abierto
    var openCollapse = document.querySelector('.collapse.show');
    if (openCollapse) {
      var span = openCollapse.querySelector('span[id^="copiado-"]');
      if (span) {
        span.classList.remove('d-none');
        setTimeout(function() {
          span.classList.add('d-none');
        }, 1500);
      }
    }
  });
}
