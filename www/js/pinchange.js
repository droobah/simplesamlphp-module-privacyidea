function togglesubmit(state) {
    document.getElementById("regularsubmit").disabled = !state;

    if (state) {
        document.getElementById("regularsubmit").removeAttribute("disabled");
    } else {
        document.getElementById("regularsubmit").setAttribute("disabled","disabled");
    }
}

function validatepin() {
    var newpin = document.getElementById("PIN").value;
    var confirmpin = document.getElementById("ConfirmPIN").value;

    if (newpin == confirmpin) {
        togglesubmit(newpin.length >= 4);
    } else {
        togglesubmit(false);
    }
}

function isnumber(evt) {
    var charCode = (evt.which) ? evt.which : event.keyCode;
    if (charCode > 31 && (charCode != 46 &&(charCode < 48 || charCode > 57)))
        return false;
    return true;
}