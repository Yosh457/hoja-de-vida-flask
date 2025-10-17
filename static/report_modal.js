document.addEventListener('DOMContentLoaded', function() {
    const modal = document.getElementById('report-modal');
    const reportForm = document.getElementById('report-form');
    const cancelBtn = document.getElementById('cancel-report');
    const factorSelect = document.getElementById('report_factor_filtro');

    // Función para abrir el modal
    function openReportModal(event) {
        event.preventDefault(); // Evita que el enlace navegue

        const target = event.currentTarget;
        const pdfUrl = target.dataset.pdfUrl; // URL base para el PDF
        const factores = JSON.parse(target.dataset.factores || '[]');

        // Llenar el select de factores
        factorSelect.innerHTML = '<option value="">Todos</option>'; // Resetear
        factores.forEach(factor => {
            const option = document.createElement('option');
            option.value = factor.id;
            option.textContent = factor.nombre;
            factorSelect.appendChild(option);
        });

        // Establecer la URL base en el formulario
        reportForm.action = pdfUrl;

        // Mostrar el modal
        modal.style.display = 'flex';
    }

    // Función para cerrar el modal
    function closeReportModal() {
        modal.style.display = 'none';
    }

    // Asignar los eventos
    document.querySelectorAll('.open-report-modal').forEach(button => {
        button.addEventListener('click', openReportModal);
    });

    if (cancelBtn) {
        cancelBtn.addEventListener('click', closeReportModal);
    }
});