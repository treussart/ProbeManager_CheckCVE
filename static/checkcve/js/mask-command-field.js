function action() {
    if(django.jQuery( "#id_instaled_by option:selected" ).text() === "manual"){
        django.jQuery(".form-row.field-command").fadeIn("slow");
    }else{
        django.jQuery(".form-row.field-command").fadeOut("fast");
    }
}
django.jQuery(document).ready(function() {
    action();
    django.jQuery("select[name='instaled_by']").change(function(){
        action();
    });
});
