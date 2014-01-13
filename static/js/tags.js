window.onload = function() {

	$(function(){
		$(".tag").tipTip({delay: 0, defaultPosition: "top"});
	});

    $('#submitIOC').click( function() {
        window.location = '/tags/ioc/' + $('#ioc_query').val();
        return false;
    });
};