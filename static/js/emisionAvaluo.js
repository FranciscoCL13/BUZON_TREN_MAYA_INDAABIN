document.addEventListener("DOMContentLoaded", function () {
  const form = document.getElementById("emision");
  const claveActual = document.getElementById("clave_solicitud").value;
  const claveGuardada = sessionStorage.getItem("clave_solicitud");

if (claveActual !== claveGuardada) {
  localStorage.removeItem("emisionAvaluoData");
  sessionStorage.clear();
}

  // Al cargar, llenar campos con datos guardados en localStorage (excepto archivos)
  const savedData = JSON.parse(localStorage.getItem("emisionAvaluoData")) || {};
  for (const key in savedData) {
    const input = form.elements.namedItem(key);
    if (input && input.type !== "file") {
      input.value = savedData[key];
    }
  }

  // Guardar cambios en localStorage cada vez que cambia un campo (excepto archivos)
  form.addEventListener("input", function () {
    const formData = new FormData(form);
    let data = {};
    formData.forEach((value, key) => {
      if (value instanceof File) return; // ignorar archivos
      data[key] = value;
    });
    localStorage.setItem("emisionAvaluoData", JSON.stringify(data));
  });

  // Enviar datos cuando se envía el formulario, incluyendo archivos
  form.addEventListener("submit", function (e) {
    e.preventDefault();

    const formData = new FormData(form);

    // Guardar en sessionStorage los datos necesarios para el paso de firmado
    const claveSolicitud = form.elements["clave_solicitud"].value;
    sessionStorage.setItem('clave_solicitud', claveSolicitud);
    sessionStorage.setItem("servidor", form.elements["servidor"].value);
    sessionStorage.setItem("valor_terreno", form.elements["valor_terreno"].value);
    sessionStorage.setItem("perito_avaluo", form.elements["perito_avaluo"].value);
    sessionStorage.setItem("superficie_metros", form.elements["superficie_metros"].value);
    sessionStorage.setItem("clave_avaluo_maestro", form.elements["clave_avaluo_maestro"].value);
    sessionStorage.setItem("uso_terreno", form.elements["uso_terreno"].value);
    sessionStorage.setItem("archivo_avaluo", form.elements["archivo_avaluo"].value);


    // Guardar nombre del archivo para el resumen (opcional)
    const archivo = form.elements["archivo_avaluo"].files[0];
    if (archivo) {
      sessionStorage.setItem("archivoNombre", archivo.name);
      // Puedes calcular hash si quieres y guardarlo también
    }

    fetch("/emisionAvaluo/guardar", {
      method: "POST",
      body: formData,
    })
      .then((res) => (res.ok ? res.json() : Promise.reject("Error en la solicitud")))
      .then((data) => {
        localStorage.removeItem("emisionAvaluoData");
        form.reset();
        window.location.href = `/emisionAvaluo/firmado/${claveSolicitud}`;
      })
      .catch((err) => {
        console.error(err);
        alert("Error al enviar el formulario.");
      });
  });
});
