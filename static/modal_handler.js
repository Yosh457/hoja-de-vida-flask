// static/modal_handler.js
function setupEditConfirmation() {
    const editForm = document.getElementById('edit-user-form');
    const modal = document.getElementById('confirmation-modal');
    const confirmBtn = document.getElementById('confirm-save');
    const cancelBtn = document.getElementById('cancel-save');

    if (!editForm || !modal) return;

    editForm.addEventListener('submit', function(event) {
        // Prevenimos el envío normal del formulario
        event.preventDefault();
        // Mostramos el modal
        modal.style.display = 'flex';
    });

    confirmBtn.addEventListener('click', function() {
        // Si se confirma, enviamos el formulario
        editForm.submit();
    });

    cancelBtn.addEventListener('click', function() {
        // Si se cancela, ocultamos el modal
        modal.style.display = 'none';
    });
}
// Ejecutamos la función cuando la página cargue
document.addEventListener('DOMContentLoaded', setupEditConfirmation);