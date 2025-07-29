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
