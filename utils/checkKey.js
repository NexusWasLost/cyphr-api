export const isLikelyValidKey = function(secret){
    const trimmed = secret.trim();

    //min char length of 16 and max of 192
    if(trimmed.length < 16 || trimmed.length > 192) return false;

    //return false if a whitespace character is found
    if(/\s/.test(trimmed)) return false;

    if(!(/^[A-Za-z0-9\-_.=+\/]+$/.test(trimmed))) return false;

    return true;
}
