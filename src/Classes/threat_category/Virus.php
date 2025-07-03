<?php
namespace Cyford\Security\Classes\ThreatCategory;

class Virus extends BaseThreatDetector
{
    protected string $category = 'virus';
    
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
            'is_threat' => $totalScore >= 80, // High threshold for virus
            'total_score' => $totalScore,
            'matches' => $results,
            'category' => $this->category
        ];
    }
}