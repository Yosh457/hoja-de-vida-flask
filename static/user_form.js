document.addEventListener('DOMContentLoaded', function () {
    const establecimientoSelect = document.getElementById('establecimiento-select');
    const unidadSelect = document.getElementById('unidad-select');

    function fetchUnidades(establecimientoId, selectedUnidadId = null) {
        // Si no hay establecimiento, deshabilita y resetea el campo de unidad.
        if (!establecimientoId) {
            unidadSelect.innerHTML = '<option value="" disabled selected>Selecciona un establecimiento primero...</option>';
            unidadSelect.disabled = true;
            return;
        }

        // Realiza una petición a nuestra API para obtener las unidades.
        fetch(`/api/unidades/${establecimientoId}`)
            .then(response => response.json())
            .then(data => {
                // Limpia el menú de unidades.
                unidadSelect.innerHTML = '<option value="" disabled selected>Selecciona una unidad...</option>';
                
                // Llena el menú con las unidades recibidas.
                data.forEach(unidad => {
                    const option = document.createElement('option');
                    option.value = unidad.id;
                    option.textContent = unidad.nombre;
                    // Si estamos editando y esta es la unidad correcta, la pre-seleccionamos.
                    if (selectedUnidadId && unidad.id == selectedUnidadId) {
                        option.selected = true;
                    }
                    unidadSelect.appendChild(option);
                });

                // Habilita el menú de unidades.
                unidadSelect.disabled = false;
            })
            .catch(error => {
                console.error('Error al cargar las unidades:', error);
                unidadSelect.disabled = true;
            });
    }

    // Evento que se dispara cuando cambia el establecimiento seleccionado.
    establecimientoSelect.addEventListener('change', function () {
        fetchUnidades(this.value);
    });

    // Lógica para la página de edición: cargar las unidades del establecimiento actual al inicio.
    // Verificamos si existe un 'data-selected-unidad-id' en el select de unidades.
    if (unidadSelect.dataset.selectedUnidadId) {
        const initialEstablecimientoId = establecimientoSelect.value;
        const initialUnidadId = unidadSelect.dataset.selectedUnidadId;
        if (initialEstablecimientoId) {
            fetchUnidades(initialEstablecimientoId, initialUnidadId);
        }
    }
});