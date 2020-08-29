// Call the dataTables jQuery plugin
$(document).ready(function() {
  $('#dataTable').DataTable();
});

$(document).ready(function() {
  $('#top10table').DataTable( {
      "order": [[ 1, "desc" ]],
      "searching": false,
      "bPaginate": false,
      "paging": false,
      "info": false
  } );
});