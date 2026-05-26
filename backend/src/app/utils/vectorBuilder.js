function buildVectors(tfidf){

    const terms = new Set();

    tfidf.documents.forEach(doc => {
        Object.keys(doc).forEach(term => {
            if(term !== '__key'){
                terms.add(term);
            }
        });
    });

    const termList = [...terms];

    const vectors = [];

    for(let i=0; i<tfidf.documents.length; i++){

        const vector = termList.map(term => 
            tfidf.tfidf(term, i)
        );

        vectors.push(vector);
    }

    return vectors;
}

module.exports = {
    buildVectors
}