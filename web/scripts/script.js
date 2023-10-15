var table = $('#hashes').DataTable( {
    serverSide: true,
    ajax: '/data-source'
} );

// Attach a submit handler to the form
$( "#download" ).submit(function( event ) {
 
  // Stop form from submitting normally
  event.preventDefault();
 
  // Get some values from elements on the page:
  var $form = $( this ),
    term = $form.find( "input[name='hashes']" ).val(),
    url = $form.attr( "action" );
 
  // Send the data using post
  var posting = $.post( url, { hashes: term } );
 
  // Put the results in a div
  posting.done(function( data ) {
    table.ajax.reload( null, false ); // user paging is not reset on reload
  });
});


setInterval( function () {
    table.ajax.reload( null, false ); // user paging is not reset on reload
}, 30000 );