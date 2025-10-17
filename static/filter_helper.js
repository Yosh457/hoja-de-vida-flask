document.addEventListener('DOMContentLoaded', function () {
    const factorSelect = document.getElementById('factor_filtro');
    const subfactorSelect = document.getElementById('subfactor_filtro');

    // Leemos los datos desde el div oculto en el HTML
    const filterDataEl = document.getElementById('filter-data');
    let allSubfactors = [];
    let selectedSubfactor = '';

    if (filterDataEl) {
        try {
            // Usamos JSON.parse para convertir el string de datos en un objeto JavaScript
            allSubfactors = JSON.parse(filterDataEl.dataset.subfactores || '[]');
        } catch (e) {
            console.error('Error al procesar los datos de subfactores:', e);
        }
        selectedSubfactor = filterDataEl.dataset.selectedSubfactor || '';
    }

    function updateSubfactorOptions() {
        const selectedFactorId = factorSelect.value;
        subfactorSelect.innerHTML = ''; // Limpiar opciones

        if (selectedFactorId) {
            subfactorSelect.disabled = false;
            let placeholder = document.createElement('option');
            placeholder.value = "";
            placeholder.textContent = "Todos los Sub-Factores";
            subfactorSelect.appendChild(placeholder);

            // Filtrar y añadir las opciones de sub-factor
            allSubfactors.forEach(subfactor => {
                if (subfactor.factor_id == selectedFactorId) {
                    let option = document.createElement('option');
                    option.value = subfactor.id;
                    option.textContent = subfactor.nombre;
                    // Si este es el subfactor que ya estaba filtrado, lo pre-seleccionamos
                    if (subfactor.id == selectedSubfactor) {
                        option.selected = true;
                    }
                    subfactorSelect.appendChild(option);
                }
            });
        } else {
            subfactorSelect.disabled = true;
            let placeholder = document.createElement('option');
            placeholder.value = "";
            placeholder.textContent = "Selecciona un factor primero...";
            subfactorSelect.appendChild(placeholder);
        }
    }

    factorSelect.addEventListener('change', updateSubfactorOptions);

    // Ejecutar una vez al cargar la página para establecer el estado inicial correcto
    updateSubfactorOptions();
});