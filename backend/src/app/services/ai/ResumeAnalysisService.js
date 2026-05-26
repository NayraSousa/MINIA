const { pipeline } = require('@xenova/transformers');
const cosineSimilarity =
require('compute-cosine-similarity');

let extractor = null;

// Carrega o modelo uma única vez
async function loadModel() {

    if (!extractor) {

        extractor = await pipeline(
            'feature-extraction',
            'Xenova/all-MiniLM-L6-v2'
        );

    }

    return extractor;
}

async function generateEmbedding(text){

    const model = await loadModel();

    const output = await model(
        text,
        {
            pooling: 'mean',
            normalize: true
        }
    );

    return Array.from(output.data);
}

module.exports = {

    async analyze(
        resumeText,
        jobDescription
    ){

        const resumeVector =
            await generateEmbedding(
                resumeText
            );

        const jobVector =
            await generateEmbedding(
                jobDescription
            );

        const similarity =
            cosineSimilarity(
                resumeVector,
                jobVector
            );

        const score =
            Math.round(
                similarity * 100
            );

        return {

            score,

            similarity:
                similarity.toFixed(2),

            status:
                score >= 75
                ? 'Alta compatibilidade'
                : score >= 45
                ? 'Compatibilidade média'
                : 'Baixa compatibilidade'
        };

    }

}