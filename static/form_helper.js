// Este código se ejecutará cuando todo el contenido de la página se haya cargado.
document.addEventListener('DOMContentLoaded', function() {

    // 1. Obtenemos los dos menús desplegables por su ID.
    const factorSelect = document.getElementById('factor-select');
    const subfactorSelect = document.getElementById('subfactor-select');
    
    // Guardamos una copia del texto original del placeholder.
    const originalPlaceholderText = subfactorSelect.options[0].textContent;
    const originalSubfactorOptions = Array.from(subfactorSelect.options)

    // 2. Nos ponemos a "escuchar" si hay algún cambio en el menú de Factores.
    factorSelect.addEventListener('change', function() {
        
        // Obtenemos el ID del factor que se ha seleccionado.
        const selectedFactorId = factorSelect.value;
        
        // Limpiamos el menú de sub-factores, dejando solo la primera opción ("Selecciona...").
        subfactorSelect.innerHTML = '';

        // Creamos una nueva opción placeholder para poder modificarla.
        const placeholderOption = document.createElement('option');
        placeholderOption.value = "";
        placeholderOption.disabled = true;
        placeholderOption.selected = true;

        // 3. Si se ha seleccionado un factor válido...
        if (selectedFactorId) {
            // Habilitamos el menú de sub-factores.
            subfactorSelect.disabled = false;
            // Cambiamos el texto del placeholder.
            placeholderOption.textContent = "Selecciona un sub-factor";
            subfactorSelect.appendChild(placeholderOption);
            // Filtramos las opciones originales para encontrar las que coinciden.
            const filteredOptions = originalSubfactorOptions.filter(option => {
                // Comparamos el 'data-factor-id' de cada opción con el ID del factor seleccionado.
                return option.dataset.factorId === selectedFactorId;
            });
            
            // 4. Añadimos las opciones filtradas de vuelta al menú de sub-factores.
            filteredOptions.forEach(option => {
                if (option.value) { // Nos aseguramos de no añadir placeholders vacíos
                    subfactorSelect.appendChild(option.cloneNode(true));
                }
            });
        } else {
            // Deshabilitamos el menú.
            subfactorSelect.disabled = true;
            // Restauramos el texto original del placeholder.
            placeholderOption.textContent = originalPlaceholderText;
            subfactorSelect.appendChild(placeholderOption);
        }
    });
});