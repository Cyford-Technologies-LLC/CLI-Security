<?php
namespace Cyford\Security\Classes\ThreatCategory;

class Phishing extends BaseThreatDetector
{
    protected string $category = 'phishing';
    
    public function analyze(array $headers, string $body): array
    {
        $results = [];
        $totalScore = 0;
        
        $algorithms = $this->getAlgorithms();
        
        foreach ($algorithms as $algorithm) {
            if ($this->executeAlgorithm($algorithm, $headers, $body)) {
                $results[] = [
                    'algorithm' => $algorithm['name'],
                    'score' => $algorithm['score'],
                    'pattern' => $algorithm['pattern']
                ];
                $totalScore += $algorithm['score'];
            }
        }
        
        return [
            'is_threat' => $totalScore >= 50, // Phishing threshold
            'total_score' => $totalScore,
            'matches' => $results,
            'category' => $this->category
        ];
    }
}