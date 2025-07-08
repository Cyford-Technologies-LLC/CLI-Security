<?php
namespace Cyford\Security\Classes\ThreatCategory;

use Cyford\Security\Classes\Database;


class Spam extends BaseThreatDetector
{
    protected string $category = 'spam';
    
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
            'is_threat' => $totalScore >= ($this->config['postfix']['spam_handling']['threshold'] ?? 70),
            'total_score' => $totalScore,
            'matches' => $results,
            'category' => $this->category
        ];
    }
}